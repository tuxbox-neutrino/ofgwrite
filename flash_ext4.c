#include "ofgwrite.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

/* Persistent trace on userdata partition top-level (outside any linuxrootfsN/
 * subdir). Survives reboot AND rootfs-wipe. Read back after reboot via:
 *   debugfs -R "dump /ofgwrite-trace.log /tmp/trace.log" /dev/mmcblk0p23
 * fopen fails silently if /oldroot_remount is not mounted yet. */
void flash_diag_log(const char *fmt, ...)
{
	FILE *km = fopen("/dev/kmsg", "w");
	FILE *tf = fopen("/oldroot_remount/ofgwrite-trace.log", "a");
	va_list ap;

	if (km)
	{
		va_start(ap, fmt);
		fprintf(km, "<4>ofgwrite: ");
		vfprintf(km, fmt, ap);
		va_end(ap);
		fclose(km);
	}
	if (tf)
	{
		time_t now = time(NULL);
		struct tm tm;
		gmtime_r(&now, &tm);
		fprintf(tf, "%04d-%02d-%02dT%02d:%02d:%02dZ ",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec);
		va_start(ap, fmt);
		vfprintf(tf, fmt, ap);
		va_end(ap);
		fflush(tf);
		fsync(fileno(tf));
		fclose(tf);
	}
}

#define kmsg_log flash_diag_log

/* Backup path retained by flash_unpack_rootfs() for deletion after
 * kernel_flash completes. See comment in flash_unpack_rootfs(). */
static char pending_backup_path[1000] = "";

void flash_unpack_rootfs_cleanup_backup(void)
{
	if (pending_backup_path[0] == '\0')
		return;
	flash_diag_log("rootfs: deferred cleanup of backup %s\n",
		pending_backup_path);
	rm_rootfs(pending_backup_path, 1, 0);
	rmdir(pending_backup_path);
	pending_backup_path[0] = '\0';
	sync();
}

static void log_extract_target_space(const char* filename, const char* directory)
{
	struct statvfs vfs;
	struct stat archive;
	unsigned long long free_bytes;

	if (statvfs(directory, &vfs) != 0)
	{
		my_printf("Warning: statvfs failed for %s: %s\n", directory, strerror(errno));
		return;
	}

	if (stat(filename, &archive) != 0)
	{
		my_printf("Warning: stat failed for %s: %s\n", filename, strerror(errno));
		return;
	}

	free_bytes = (unsigned long long)vfs.f_bavail * (unsigned long long)vfs.f_frsize;
	my_printf("Extract target free bytes: %llu, archive bytes: %lld\n",
		free_bytes, (long long)archive.st_size);
	if (free_bytes < (unsigned long long)archive.st_size)
	{
		my_printf("Warning: free bytes are below archive size, extraction is likely to fail\n");
	}
}

int flash_ext4_kernel(char* device, char* filename, off_t kernel_file_size, int quiet, int no_write)
{
	char buffer[512];

	// Preflight: stat source and device so we can distinguish missing-path
	// from permission/other errors in the kernel ring buffer.
	struct stat src_st, dev_st;
	int src_stat_rc = stat(filename, &src_st);
	int src_stat_err = errno;
	int dev_stat_rc = stat(device, &dev_st);
	int dev_stat_err = errno;
	kmsg_log("kernel_flash preflight: src=%s stat_rc=%d err=%s "
		"size=%lld dev=%s stat_rc=%d err=%s\n",
		filename, src_stat_rc,
		src_stat_rc == 0 ? "ok" : strerror(src_stat_err),
		src_stat_rc == 0 ? (long long)src_st.st_size : -1LL,
		device, dev_stat_rc,
		dev_stat_rc == 0 ? "ok" : strerror(dev_stat_err));

	// Open kernel file
	FILE* kernel_file;
	kernel_file = fopen(filename, "rb");
	if (kernel_file == NULL)
	{
		int e = errno;
		my_printf("Error while opening kernel file %s: %s\n", filename, strerror(e));
		kmsg_log("kernel_flash: fopen source FAILED path=%s errno=%d (%s)\n",
			filename, e, strerror(e));
		return 0;
	}

	// Open kernel device
	FILE* kernel_dev;
	kernel_dev = fopen(device, "wb");
	if (kernel_dev == NULL)
	{
		int e = errno;
		my_printf("Error while opening kernel device %s: %s\n", device, strerror(e));
		kmsg_log("kernel_flash: fopen device FAILED path=%s errno=%d (%s)\n",
			device, e, strerror(e));
		fclose(kernel_file);
		return 0;
	}

	set_step("Writing ext4 kernel");
	int ret;
	long long readBytes = 0;
	int current_percent = 0;
	int new_percent     = 0;
	while (!feof(kernel_file))
	{
		// Don't add my_printf for debugging! Debug messages will be written to kernel device!
		ret = fread(buffer, 1, sizeof(buffer), kernel_file);
		if (ret == 0)
		{
			if (feof(kernel_file))
				continue;
			int e = errno;
			my_printf("Error reading kernel file: %s\n", strerror(e));
			kmsg_log("kernel_flash: fread FAILED after %lld bytes errno=%d (%s)\n",
				readBytes, e, strerror(e));
			fclose(kernel_file);
			fclose(kernel_dev);
			return 0;
		}
		readBytes += ret;
		new_percent = readBytes * 100/ kernel_file_size;
		if (current_percent < new_percent)
		{
			set_step_progress(new_percent);
			current_percent = new_percent;
		}
		if (!no_write)
		{
			ret = fwrite(buffer, ret, 1, kernel_dev);
			if (ret != 1)
			{
				int e = errno;
				my_printf("Error writing kernel file to kernel device: %s\n", strerror(e));
				kmsg_log("kernel_flash: fwrite FAILED after %lld bytes errno=%d (%s)\n",
					readBytes, e, strerror(e));
				fclose(kernel_file);
				fclose(kernel_dev);
				return 0;
			}
		}
	}

	fclose(kernel_file);
	fclose(kernel_dev);

	kmsg_log("kernel_flash: success path=%s bytes=%lld device=%s\n",
		filename, readBytes, device);
	return 1;
}

int rm_rootfs(char* directory, int quiet, int no_write)
{
	optind = 0; // reset getopt_long
	char* argv[] = {
		"rm",		// program name
		"-r",		// recursive
		"-f",		// force
		directory,	// directory
		NULL
	};
	int argc = (int)(sizeof(argv) / sizeof(argv[0])) - 1;

	if (!quiet)
		my_printf("Delete rootfs: rm -r -f %s\n", directory);
	if (!no_write)
		if (rm_main(argc, argv) != 0)
			return 0;

	return 1;
}

int untar_rootfs(char* filename, char* directory, int quiet, int no_write)
{
	optind = 0; // reset getopt_long
	char* argv[] = {
		"tar",		// program name
		"-x",		// extract
		"-f",
		filename,	// file
		"-C",
		directory,	// untar to directory
		NULL
	};
	int argc = (int)(sizeof(argv) / sizeof(argv[0])) - 1;

	if (!quiet)
		my_printf("Untar: tar xf %s\n", filename);
	if (access(directory, F_OK) != 0)
	{
		my_printf("Error: rootfs target directory missing: %s (%s)\n", directory, strerror(errno));
		return 0;
	}
	log_extract_target_space(filename, directory);
	if (!no_write)
	{
		if (tar_main(argc, argv) != 0)
		{
			my_printf("Error: tar extraction failed for %s into %s\n", filename, directory);
			return 0;
		}
	}

	return 1;
}

int flash_unpack_rootfs(char* filename, int quiet, int no_write)
{
	int ret;
	char path[1000];
	char backup_path[1000];
	int has_backup = 0;
	int has_subdir = (current_rootfs_sub_dir[0] != '\0' && rootsubdir_check == 0);

	strcpy(path, "/oldroot_remount/");
	if (has_subdir) // box with rootSubDir feature
	{
		strcat(path, rootfs_sub_dir);
		strcat(path, "/");
	}

	if (!no_write)
	{
		if (has_subdir)
		{
			// Safety: rename old rootfs instead of deleting immediately.
			// If extraction fails, the old content can be restored.
			snprintf(backup_path, sizeof(backup_path),
				"/oldroot_remount/%s.old/", rootfs_sub_dir);
			// Remove stale backup from a previous failed attempt
			rm_rootfs(backup_path, quiet, 0);
			rmdir(backup_path);

			set_step("Moving old rootfs");
			my_printf("Renaming %s -> %s\n", path, backup_path);
			if (rename(path, backup_path) == 0)
			{
				has_backup = 1;
				// Recreate empty target directory
				if (mkdir(path, 0777) != 0)
				{
					my_printf("Error creating rootfs dir %s: %s\n", path, strerror(errno));
					// Restore backup
					rename(backup_path, path);
					return 0;
				}
			}
			else
			{
				my_printf("Rename failed (%s), falling back to delete\n", strerror(errno));
				set_step("Deleting rootfs");
				rm_rootfs(path, quiet, 0);
			}
		}
		else
		{
			// No subdir: original delete behavior (active-slot pivot_root path)
			set_step("Deleting rootfs");
			rm_rootfs(path, quiet, 0);
		}
	}

	// Ensure target subdir exists before tar extraction
	if (!no_write && has_subdir)
	{
		if (mkdir(path, 0777) != 0 && errno != EEXIST)
		{
			my_printf("Error creating rootfs directory %s: %s\n", path, strerror(errno));
			if (has_backup)
			{
				my_printf("Restoring previous rootfs from backup\n");
				rmdir(path);
				rename(backup_path, path);
			}
			return 0;
		}
	}

	set_step("Extracting rootfs");
	set_step_progress(0);
	if (!untar_rootfs(filename, path, quiet, no_write))
	{
		my_printf("Error extracting rootfs\n");
		if (has_backup)
		{
			my_printf("Restoring previous rootfs from backup\n");
			set_step("Restoring old rootfs");
			rm_rootfs(path, quiet, 0);
			rmdir(path);
			rename(backup_path, path);
		}
		return 0;
	}

	// Success: DEFER backup deletion until after kernel_flash.
	// The image files (uImage, rootfs.tar.bz2) live inside the backup
	// (e.g. /oldroot_remount/linuxrootfs4.old/media/hdd/ofgwrite-caller-XXXX/)
	// and are still referenced via the /media/ bind mount. Deleting the
	// backup here would unlink the kernel source before kernel_flash() can
	// read it, causing ENOENT. The caller invokes
	// flash_unpack_rootfs_cleanup_backup() once kernel_flash succeeds.
	if (has_backup)
	{
		strncpy(pending_backup_path, backup_path,
			sizeof(pending_backup_path) - 1);
		pending_backup_path[sizeof(pending_backup_path) - 1] = '\0';
		flash_diag_log("rootfs: backup retained for post-kernel-flash cleanup: %s\n",
			pending_backup_path);
	}

	// sync filesystem double because of sdcard
	sync();
	sync();
	sleep(1);
	ret = chdir("/"); // needed to be able to umount filesystem
	if (ret != 0)
	{
		my_printf("Warning: chdir(\"/\") failed: %s\n", strerror(errno));
	}
	return 1;
}
