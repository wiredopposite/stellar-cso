#!/usr/bin/python3
# Copyright 2018 David O'Rourke <david.orourke@gmail.com>
# Copyright 2022 MakeMHz LLC <contact@makemhz.com>
# Based on ciso from https://github.com/jamie/ciso

import os
import struct
import sys
import lz4.frame

CISO_MAGIC = 0x4F534943 # CISO
CISO_HEADER_SIZE = 0x18 # 24
CISO_BLOCK_SIZE = 0x800 # 2048
CISO_HEADER_FMT = '<LLQLBBxx' # Little endian
CISO_PLAIN_BLOCK = 0x80000000

XISO_SECTOR_SIZE = 0x800
XISO_MAGIC = b"MICROSOFT*XBOX*MEDIA"

#assert(struct.calcsize(CISO_HEADER_FMT) == CISO_HEADER_SIZE)

image_offset = 0

class BinaryTreeNode:
    def __init__(self, DirectorySize=0, DirectoryPos=0, Offset=0):
        self.DirectorySize = DirectorySize
        self.DirectoryPos = DirectoryPos
        self.Offset = Offset

def get_terminal_size(fd=sys.stdout.fileno()):
	try:
		import fcntl, termios
		hw = struct.unpack("hh", fcntl.ioctl(
			fd, termios.TIOCGWINSZ, '1234'))
	except:
		try:
			hw = (os.environ['LINES'], os.environ['COLUMNS'])
		except:
			hw = (25, 80)
	return hw

(console_height, console_width) = get_terminal_size()

def update_progress(progress):
	barLength = console_width - len("Progress: 100% []") - 1
	block = int(round(barLength*progress)) + 1
	text = "\rProgress: [{blocks}] {percent:.0f}%".format(
			blocks="#" * block + "-" * (barLength - block),
			percent=progress * 100)
	sys.stdout.write(text)
	sys.stdout.flush()

def get_data_sectors(f, sector_offset):
	# Based on xbox_shrinker https://github.com/Qubits01/xbox_shrinker
	# and Repackinator https://github.com/Team-Resurgent/Repackinator

    XISO_HEADER_SECTOR = 0x20 # 32
    XISO_ATTRIBUTE_DIRECTORY = 0x10

    print("Reading directory table")

    data_sectors = {sector_offset + XISO_HEADER_SECTOR, sector_offset + XISO_HEADER_SECTOR + 1}

    # Get directory table root sector and size from header
    f.seek(((sector_offset + XISO_HEADER_SECTOR) * XISO_SECTOR_SIZE) + len(XISO_MAGIC))
    root_sector, root_size = struct.unpack('<II', f.read(8))
    tree_nodes = [BinaryTreeNode(
        DirectorySize = root_size, 
        DirectoryPos  = root_sector * XISO_SECTOR_SIZE
        )]

    while tree_nodes:
        current_tree_node = tree_nodes.pop(0)
        
        current_position = (sector_offset * XISO_SECTOR_SIZE) + current_tree_node.DirectoryPos + current_tree_node.Offset * 4

        # Get range of sectors this directory entry encompasses
        end_position = (current_position // XISO_SECTOR_SIZE) + ((current_tree_node.DirectorySize - (current_tree_node.Offset * 4) + 2047) // XISO_SECTOR_SIZE)
        data_sectors.update(range(current_position // XISO_SECTOR_SIZE, end_position))
        
        if (current_tree_node.Offset * 4) < current_tree_node.DirectorySize:
            f.seek(current_position)
            
            # Read entry info
            left, right, sector, size, attribute = struct.unpack('<HHIIB', f.read(13))

            if left and left != 0xFFFF:
                tree_nodes.append(BinaryTreeNode(
                    DirectorySize = current_tree_node.DirectorySize, 
                    DirectoryPos  = current_tree_node.DirectoryPos, 
                    Offset        = left
                    ))
            
            if (attribute & XISO_ATTRIBUTE_DIRECTORY) and size:
                tree_nodes.append(BinaryTreeNode(
                    DirectorySize = size, 
                    DirectoryPos  = sector * XISO_SECTOR_SIZE
                    ))
            elif size:
                data_sectors.update(range(sector_offset + sector, sector_offset + sector + ((size + 2047) // XISO_SECTOR_SIZE)))

            if right:
                tree_nodes.append(BinaryTreeNode(
                    DirectorySize = current_tree_node.DirectorySize, 
                    DirectoryPos  = current_tree_node.DirectoryPos, 
                    Offset        = right
                    ))
                
    return data_sectors

def get_security_sectors(f, data_sectors, sector_offset):
	# Based on xbox_shrinker https://github.com/Qubits01/xbox_shrinker
	# and Repackinator https://github.com/Team-Resurgent/Repackinator

    print("Indexing security sectors")

    security_sectors = set()
    
    in_empty_range = False
    empty_start = 0
    total_sectors = 0x345B60 + 1

    data_sectors_offset = {sector + sector_offset for sector in data_sectors}

    for sector_index, _ in enumerate(range(total_sectors)):
        current_sector = sector_offset + sector_index
        f.seek(current_sector * XISO_SECTOR_SIZE)

        # Don't really need to check the whole sector, can probably reduce this
        sector_buffer = f.read(XISO_SECTOR_SIZE)

        # Check if the sector is empty and if it's part of data sectors
        is_empty_sector = all(byte == 0 for byte in sector_buffer)
        is_data_sector = current_sector in data_sectors_offset

        # If we find an empty sector and we aren't in a range of empty sectors
        if is_empty_sector and not in_empty_range and not is_data_sector:
            empty_start = current_sector
            in_empty_range = True

        # If we find a non-empty sector at the end of a range of empty ones
        elif not is_empty_sector and in_empty_range:
            empty_end = current_sector - 1
            in_empty_range = False

            if empty_end - empty_start == 0xFFF:
                security_sectors.update(range(empty_start, empty_end + 1))

        update_progress(sector_index / total_sectors)

    print()
    return security_sectors

def check_file_size(f):
	global image_offset

	f.seek(0, os.SEEK_END)
	total_infile_blocks = f.tell() // CISO_BLOCK_SIZE
	file_size = f.tell() - image_offset
	ciso = {
			'magic': CISO_MAGIC,
			'ver': 2,
			'block_size': CISO_BLOCK_SIZE,
			'total_bytes': file_size,
			'total_blocks': int(file_size / CISO_BLOCK_SIZE),
			'align': 2,
			}
	return ciso, total_infile_blocks

def write_cso_header(f, ciso):
	f.write(struct.pack(CISO_HEADER_FMT,
		ciso['magic'],
		CISO_HEADER_SIZE,
		ciso['total_bytes'],
		ciso['block_size'],
		ciso['ver'],
		ciso['align']
		))

def write_block_index(f, block_index):
	for index, block in enumerate(block_index):
		try:
			f.write(struct.pack('<I', block))
		except Exception as e:
			print("Writing block={} with data={} failed.".format(
				index, block))
			print(e)
			sys.exit(1)

def detect_iso_type(f):
	global image_offset

	# Detect if the image is a REDUMP image
	f.seek(0x18310000)
	buffer = f.read(20)
	if buffer == XISO_MAGIC:
		print("REDUMP image detected")
		image_offset = 0x18300000
		return

	# Detect if the image is a raw XDVDFS image
	f.seek(0x10000)
	buffer = f.read(20)
	if buffer == XISO_MAGIC:
		image_offset = 0
		return

	# Print error and exit
	print("ERROR: Could not detect ISO type.")
	sys.exit(1)

# Pad file size to ATA block size * 2
def pad_file_size(f):
	f.seek(0, os.SEEK_END)
	size = f.tell()
	f.write(struct.pack('<B', 0x00) * (0x400 - (size & 0x3FF)))

def compress_iso(infile, scrub):
	lz4_context = lz4.frame.create_compression_context()

	# Replace file extension with .cso
	fout_1 = open(os.path.splitext(infile)[0] + '.1.cso', 'wb')
	fout_2 = None

	with open(infile, 'rb') as fin:
		print("Compressing '{}'".format(infile))

		# Detect and validate the ISO
		detect_iso_type(fin)

		ciso, total_infile_blocks = check_file_size(fin)

		if scrub:
			sector_offset = image_offset // XISO_SECTOR_SIZE

			# Get sectors from infile's directory table
			data_sectors = get_data_sectors(fin, sector_offset)

			# Trim to last data sector + 1 if that's less than infile size
			ciso['total_blocks'] = min(max(data_sectors) + 1, total_infile_blocks) - sector_offset
			ciso['total_bytes']  = ciso['total_blocks'] * XISO_SECTOR_SIZE

			# We don't need security sectors if input isn't a redump
			# 0x374750 is the # of blocks in a redump image minus video partition
			if sector_offset != 0 or total_infile_blocks == 0x374750:
				security_sectors = list(get_security_sectors(fin, data_sectors, sector_offset))
				data_sectors.update(security_sectors)

			# Shift data sectors to account for image offset
			data_sectors = {x - sector_offset for x in data_sectors}

		for k, v in ciso.items():
			print("{}: {}".format(k, v))

		write_cso_header(fout_1, ciso)
		block_index = [0x00] * (ciso['total_blocks'] + 1)

		# Write the dummy block index for now.
		write_block_index(fout_1, block_index)

		write_pos = fout_1.tell()
		align_b = 1 << ciso['align']
		align_m = align_b - 1

		# Alignment buffer is unsigned char.
		alignment_buffer = struct.pack('<B', 0x00) * 64

		# Progress counters
		percent_period = ciso['total_blocks'] / 100
		percent_cnt = 0

		split_fout = fout_1

		fin.seek(image_offset, os.SEEK_SET)

		for block in range(0, ciso['total_blocks']):
			# Check if we need to split the ISO (due to FATX limitations)
			# TODO: Determine a better value for this.
			if write_pos > 0xFFBF6000:
				# Create new file for the split
				fout_2     = open(os.path.splitext(infile)[0] + '.2.cso', 'wb')
				split_fout = fout_2

				# Reset write position
				write_pos  = 0

			# Write alignment
			align = int(write_pos & align_m)
			if align:
				align = align_b - align
				size = split_fout.write(alignment_buffer[:align])
				write_pos += align

			# Mark offset index
			block_index[block] = write_pos >> ciso['align']

			if scrub and block not in data_sectors:
				# Zero out padding
				raw_data = bytes([0] * ciso['block_size'])
				fin.seek(ciso['block_size'], os.SEEK_CUR)
			else:
				# Read raw data
				raw_data = fin.read(ciso['block_size'])

			raw_data_size = len(raw_data)

			# Compress block
			# Compressed data will have the gzip header on it, we strip that.
			lz4.frame.compress_begin(lz4_context, compression_level=lz4.frame.COMPRESSIONLEVEL_MAX,
				auto_flush=True, content_checksum=False, block_checksum=False, block_linked=False, source_size=False)

			compressed_data = lz4.frame.compress_chunk(lz4_context, raw_data, return_bytearray=True)
			compressed_size = len(compressed_data)

			lz4.frame.compress_flush(lz4_context)

			# Ensure compressed data is smaller than raw data
			# TODO: Find optimal block size to avoid fragmentation
			if (compressed_size + 12) >= raw_data_size:
				writable_data = raw_data

				# Next index
				write_pos += raw_data_size
			else:
				writable_data = compressed_data

				# LZ4 block marker
				block_index[block] |= 0x80000000

				# Next index
				write_pos += compressed_size

			# Write data
			split_fout.write(writable_data)

			# Progress bar
			percent = int(round((block / (ciso['total_blocks'] + 1)) * 100))
			if percent > percent_cnt:
				update_progress((block / (ciso['total_blocks'] + 1)))
				percent_cnt = percent

		# TODO: Pad file to ATA block size

		# end for block
		# last position (total size)
		# NOTE: We don't actually need this, but we're keeping it for legacy reasons.
		block_index[-1] = write_pos >> ciso['align']

		# write header and index block
		print("\nWriting block index")
		fout_1.seek(CISO_HEADER_SIZE, os.SEEK_SET)
		write_block_index(fout_1, block_index)

	# end open(infile)
	pad_file_size(fout_1)
	fout_1.close()

	if fout_2:
		pad_file_size(fout_2)
		fout_2.close()

def main(argv):
    infile = None
    scrub = False

    for arg in argv[1:]:
        if arg in ('--scrub', '-s'):
            scrub = True
        else:
            infile = arg

    if infile is None:
        print("Error: You must specify an input file.")
        sys.exit(1)

    compress_iso(infile, scrub)

if __name__ == '__main__':
	sys.exit(main(sys.argv))
