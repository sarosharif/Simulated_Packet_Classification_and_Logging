project('pkt_gen', 'c')

# Define the include directory (assuming it's outside the 'src' directory)
include_dir = include_directories('include')


# Define the source files
src_files = files('src/pkt_gen.c', 'src/classifier.c')

# Create executables with include directories and source files
executable('b1', src_files, install: true, include_directories: include_dir)
executable('b2', src_files, install: true, include_directories: include_dir)
executable('b3', src_files, install: true, include_directories: include_dir)

ini_file = 'domain_to_app.ini'
custom_target('copy script',
  input : ini_file,
  output :  ini_file,
  command : ['cp', '@INPUT@', '@OUTPUT@'],
  install : false,
  build_by_default : true)
