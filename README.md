# Minix3 Disk Util

This is a simple utility that copies files from your local drive onto a Minix3 disk image.

Usage:

```bash
./minix-disk-util <minix image> <local path> <image path>
```

- `minix image`: The path to the Minix3 disk image.
- `local path`: The source path to the file on your local drive.
- `image path`: The destination path to the file on the Minix3 disk image.

The Minix image is expected to already be formatted as a Minix disk, but can be empty otherwise.

The image destination path must be an absolute path. The utility will recursively create new directories if they do not exist, and skip over directories that do. The Utility will only copy one file at a time.

Example:

Let's say we want to copy `hello_world.elf`, `basic.elf`, `console.elf`, and `primes.elf` from a `bin` directory on our local drive to the `/apps/bin` directory on the Minix3 disk image and the `/apps/bin` directory does not exist on the disk image.

```bash
# Will create /apps/bin and copy hello_world.elf
./minix-disk-util minix.hdd bin/hello_world.elf /apps/bin/hello_world.elf
# Will traverse /apps/bin and copy basic.elf
./minix-disk-util minix.hdd bin/basic.elf /apps/bin/basic.elf
# Will traverse /apps/bin and copy console.elf
./minix-disk-util minix.hdd bin/console.elf /apps/bin/console.elf
# Etc.
./minix-disk-util minix.hdd bin/primes.elf /apps/bin/primes.elf
```

If you are copying an entire directory of files, a better approach is to use a for loop.

```bash
for BIN_PATH in bin/*.elf; do
    BIN_FILENAME=$(basename "$BIN_PATH")
    ./minix-disk-util minix.hdd "bin/$BIN_FILENAME" "/apps/bin/$BIN_FILENAME"
done
```
