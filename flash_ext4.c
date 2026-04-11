#include "ofgwrite.h"

#include <errno.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <sys/statvfs.h>
#include <unistd.h>

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

	// Open kernel file
	FILE* kernel_file;
	kernel_file = fopen(filename, "rb");
	if (kernel_file == NULL)
	{
		my_printf("Error while opening kernel file %s\n", filename);
		return 0;
	}

	// Open kernel device
	FILE* kernel_dev;
	kernel_dev = fopen(device, "wb");
	if (kernel_dev == NULL)
	{
		my_printf("Error while opening kernel device %s\n", device);
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
			my_printf("Error reading kernel file.\n");
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
				my_printf("Error writing kernel file to kernel device.\n");
				fclose(kernel_file);
				fclose(kernel_dev);
				return 0;
			}
		}
	}

	fclose(kernel_file);
	fclose(kernel_dev);

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

	// Success: delete old backup
	if (has_backup)
	{
		set_step("Cleaning up old rootfs");
		my_printf("Removing old rootfs backup %s\n", backup_path);
		rm_rootfs(backup_path, quiet, 0);
		rmdir(backup_path);
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
