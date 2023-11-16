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

class SplitInput:
    def __init__(self, file1_path, file2_path):
        self.file1 = open(file1_path, 'rb')
        self.file2 = open(file2_path, 'rb')
        self.current_file = self.file1

    def read(self, size=-1):
        data = self.current_file.read(size)
        if size != -1:
            remaining_size = size - len(data)
            # if still more requested data after the end of first file
            if remaining_size > 0 and self.current_file is self.file1:
                self.current_file = self.file2
                data += self.current_file.read(remaining_size)
        else:
            if self.current_file is self.file1:
                self.current_file = self.file2
                data += self.current_file.read()

        return data

    def seek(self, offset, whence=os.SEEK_SET):
        file1_size = os.fstat(self.file1.fileno()).st_size

        if whence == os.SEEK_SET:
            if offset < file1_size:
                self.file1.seek(offset)
                self.current_file = self.file1
                self.file2.seek(0) 
            else:
                self.file1.seek(file1_size)  # go to end of file1
                self.file2.seek(offset - file1_size)
                self.current_file = self.file2
        elif whence == os.SEEK_CUR:
            current_pos = self.file1.tell() if self.current_file is self.file1 else file1_size + self.file2.tell()
            self.seek(current_pos + offset)
        elif whence == os.SEEK_END:
            file2_size = os.fstat(self.file2.fileno()).st_size
            total_size = file1_size + file2_size
            self.seek(total_size + offset)
        else:
            raise ValueError("Invalid value for `whence`.")

    def tell(self):
        file1_pos = self.file1.tell()
        file2_pos = self.file2.tell()
        
        if self.current_file is self.file1:
            return file1_pos
        else:
            file1_size = os.fstat(self.file1.fileno()).st_size
            return file1_size + file2_pos

    def close(self):
        self.file1.close()
        self.file2.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

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

def check_file_size(f):
	global image_offset

	f.seek(0, os.SEEK_END)
	total_infile_sectors = f.tell() // XISO_SECTOR_SIZE
	file_size = f.tell() - image_offset
	ciso = {
			'magic': CISO_MAGIC,
			'ver': 2,
			'block_size': CISO_BLOCK_SIZE,
			'total_bytes': file_size,
			'total_blocks': int(file_size / CISO_BLOCK_SIZE),
			'align': 2,
			}
	return ciso, total_infile_sectors

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

def get_data_sectors(f, sector_offset):
	# Based on xbox_shrinker https://github.com/Qubits01/xbox_shrinker
	# and Repackinator https://github.com/Team-Resurgent/Repackinator

	print('Reading directory table')

	data_sectors = set()

	header_sector = sector_offset + 32
	data_sectors.add(header_sector)
	data_sectors.add(header_sector + 1)

	f.seek((header_sector << 11) + len(XISO_MAGIC))
	root_sector, root_size = struct.unpack('<II', f.read(8))
	root_offset = root_sector << 11

	tree_nodes = [BinaryTreeNode(
		DirectorySize = root_size, 
		DirectoryPos = root_offset, 
		Offset = 0
		)]

	total_nodes = 1
	processed_nodes = 0

	while len(tree_nodes) > 0:
		current_tree_node = tree_nodes[0]
		tree_nodes.pop(0)
		processed_nodes +=1

		current_position = (sector_offset << 11) + current_tree_node.DirectoryPos + current_tree_node.Offset * 4

		for i in range(current_position >> 11, (current_position >> 11) + ((current_tree_node.DirectorySize - (current_tree_node.Offset * 4) + 2047) >> 11)):
			data_sectors.add(i)
		if (current_tree_node.Offset * 4) >= current_tree_node.DirectorySize:
			continue

		f.seek(current_position)
		left, right, sector, size, attribute = struct.unpack('<HHIIB', f.read(13))

		if left == 0xFFFF:
			continue

		if left != 0:
			tree_nodes.append(BinaryTreeNode(
				DirectorySize = current_tree_node.DirectorySize,
				DirectoryPos = current_tree_node.DirectoryPos,
				Offset = left,
			))
			total_nodes += 1

		if (attribute & 0x10) != 0:
			if size > 0:
				tree_nodes.append(BinaryTreeNode(
					DirectorySize = size,
					DirectoryPos = sector << 11,
					Offset = 0,
				))
				total_nodes += 1
		else:
			if size > 0:
				for i in range(sector_offset + sector, sector_offset + sector + ((size + 2047) >> 11)):
					data_sectors.add(i)

		if right != 0:
			tree_nodes.append(BinaryTreeNode(
				DirectorySize = current_tree_node.DirectorySize,
				DirectoryPos = current_tree_node.DirectoryPos,
				Offset = right,
			))
			total_nodes += 1

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

		# Skip if sector is already in data sectors
		if current_sector in data_sectors_offset:
			if in_empty_range:
				empty_end = current_sector - 1
				in_empty_range = False

				if empty_end - empty_start == 0xFFF:
					security_sectors.update(range(empty_start, empty_end + 1))

			sector_index += 1
			continue

		f.seek(current_sector * XISO_SECTOR_SIZE)

		# Don't really need to check the whole sector but we'll be safe, costs a couple more seconds
		sector_buffer = f.read(XISO_SECTOR_SIZE)
		is_empty_sector = all(byte == 0 for byte in sector_buffer)

		# If we find an empty sector and we aren't in a range of empty sectors
		if is_empty_sector and not in_empty_range:
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

def compress_iso(fin, infile, scrub):
	lz4_context = lz4.frame.create_compression_context()

	# Replace file extension with .cso
	fout_1 = open(os.path.splitext(infile)[0] + '.1.cso', 'wb')
	fout_2 = None

	# Detect and validate the ISO
	detect_iso_type(fin)

	ciso, total_infile_sectors = check_file_size(fin)

	if scrub:
		sector_offset = image_offset // XISO_SECTOR_SIZE

		# Get sectors from infile's directory table
		data_sectors = get_data_sectors(fin, sector_offset)

		# Trim to last data sector + 1 if that comes before last infile sector
		ciso['total_blocks'] = min(max(data_sectors) + 1, total_infile_sectors) - sector_offset
		ciso['total_bytes']  = ciso['total_blocks'] * XISO_SECTOR_SIZE

		# We don't need security sectors if input isn't a redump
		# 0x374750 is the # of sectors in a redump image minus video partition
		if total_infile_sectors - sector_offset == 0x374750:
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

def get_paired_file(infile, extension):
    paired_file = infile[:-6] + extension
    if not os.path.exists(paired_file):
        return None
    return paired_file

def open_infile(infile):
	infile_no_ext, extension = os.path.splitext(infile)
	subextension = None

	if infile_no_ext.endswith('.1') or infile_no_ext.endswith('.2'):
		_, subextension = os.path.splitext(infile_no_ext)

		# Find split file parts and combine into a single file object, readable with the SplitInput class
		if subextension == '.1':
			infile2 = get_paired_file(infile, ('.2' + extension))
			if not infile2:
				# subextension .1 doesn't always mean it's a split file, continue anyway
				print(f"File has subextension '.1' but part 2 was not found, proceeding anyway.\nProcessing: '{infile}'")
				f = open(infile, 'rb')
			else:
				print(f"Processing split '{extension}' file.\nPart 1: '{infile}'\nPart 2: '{infile2}'")
				f = SplitInput(infile, infile2)
		elif subextension == '.2':
			infile1 = get_paired_file(infile, ('.1' + extension))
			if not infile1:
				print(f'Paired file for {os.path.basename(infile)} not found.')
				return False
			
			print(f"Processing split '{extension}' file.\nPart 1: '{infile1}'\nPart 2: '{infile}'")
			f = SplitInput(infile1, infile)
	else:
		print(f"Processing: '{infile}'")
		f = open(infile, 'rb')

	return f

def main(argv):
	input_path = None
	scrub = False

	for arg in argv[1:]:
		if arg in ('--scrub', '-s'):
			scrub = True
		else:
			input_path = arg

	if input_path is None:
		print("Error: You must specify an input file.")
		sys.exit(1)
	elif os.path.isfile(input_path):
		infile = input_path
		fin = open_infile(infile)
		if fin:
			compress_iso(fin, infile, scrub)
			fin.close()
		else:
			sys.exit(1)
	elif os.path.isdir(input_path):
		for root, folders, files in os.walk(input_path):
			for file in files:
				if file.endswith('.iso') and not file.endswith('.2.iso'):
					infile = os.path.join(root, file)
					fin = open_infile(infile)
					if fin:
						compress_iso(fin, infile, scrub)
						fin.close()
					else:
						print(f"Skipping '{infile}'")

if __name__ == '__main__':
	sys.exit(main(sys.argv))
