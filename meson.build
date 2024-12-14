project('pkt_gen', 'c')

# Define the include directory (assuming it's outside the 'src' directory)
include_dir = include_directories('include')

# Define the source files for the packet generator and classifier
src_files = files('src/pkt_gen.c', 'src/classifier.c')

# Define the source file for the collector
collector_src = files('src/collector.c')

# Find the ZeroMQ library
zmq_dep = dependency('libzmq', required: true)

# Create executables with include directories and source files
executable('b1', src_files, install: true, include_directories: include_dir, dependencies: zmq_dep)
executable('b2', src_files, install: true, include_directories: include_dir, dependencies: zmq_dep)
executable('b3', src_files, install: true, include_directories: include_dir, dependencies: zmq_dep)

# Create an executable for the collector
executable('collector', collector_src, install: true, include_directories: include_dir, dependencies: zmq_dep)

# Copy the ini file as part of the build process
ini_file = 'domain_to_app.ini'
custom_target('copy script',
  input : ini_file,
  output : ini_file,
  command : ['cp', '@INPUT@', '@OUTPUT@'],
  install : false,
  build_by_default : true)
