# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.25

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /opt/homebrew/Cellar/cmake/3.25.1/bin/cmake

# The command to remove a file.
RM = /opt/homebrew/Cellar/cmake/3.25.1/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/sofianeazogagh/Desktop/PROBONITE/PROBONITE/packed-PROBONITE/src

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/sofianeazogagh/Desktop/PROBONITE/PROBONITE/packed-PROBONITE/src/build

# Include any dependencies generated for this target.
include CMakeFiles/multi_baacc.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/multi_baacc.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/multi_baacc.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/multi_baacc.dir/flags.make

CMakeFiles/multi_baacc.dir/MultiBAAcc.cpp.o: CMakeFiles/multi_baacc.dir/flags.make
CMakeFiles/multi_baacc.dir/MultiBAAcc.cpp.o: /Users/sofianeazogagh/Desktop/PROBONITE/PROBONITE/packed-PROBONITE/src/MultiBAAcc.cpp
CMakeFiles/multi_baacc.dir/MultiBAAcc.cpp.o: CMakeFiles/multi_baacc.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/sofianeazogagh/Desktop/PROBONITE/PROBONITE/packed-PROBONITE/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/multi_baacc.dir/MultiBAAcc.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/multi_baacc.dir/MultiBAAcc.cpp.o -MF CMakeFiles/multi_baacc.dir/MultiBAAcc.cpp.o.d -o CMakeFiles/multi_baacc.dir/MultiBAAcc.cpp.o -c /Users/sofianeazogagh/Desktop/PROBONITE/PROBONITE/packed-PROBONITE/src/MultiBAAcc.cpp

CMakeFiles/multi_baacc.dir/MultiBAAcc.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/multi_baacc.dir/MultiBAAcc.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/sofianeazogagh/Desktop/PROBONITE/PROBONITE/packed-PROBONITE/src/MultiBAAcc.cpp > CMakeFiles/multi_baacc.dir/MultiBAAcc.cpp.i

CMakeFiles/multi_baacc.dir/MultiBAAcc.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/multi_baacc.dir/MultiBAAcc.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/sofianeazogagh/Desktop/PROBONITE/PROBONITE/packed-PROBONITE/src/MultiBAAcc.cpp -o CMakeFiles/multi_baacc.dir/MultiBAAcc.cpp.s

# Object files for target multi_baacc
multi_baacc_OBJECTS = \
"CMakeFiles/multi_baacc.dir/MultiBAAcc.cpp.o"

# External object files for target multi_baacc
multi_baacc_EXTERNAL_OBJECTS =

multi_baacc: CMakeFiles/multi_baacc.dir/MultiBAAcc.cpp.o
multi_baacc: CMakeFiles/multi_baacc.dir/build.make
multi_baacc: /usr/local/lib/libOPENFHEpke.1.0.1.dylib
multi_baacc: /usr/local/lib/libOPENFHEbinfhe.1.0.1.dylib
multi_baacc: /usr/local/lib/libOPENFHEcore.1.0.1.dylib
multi_baacc: CMakeFiles/multi_baacc.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/sofianeazogagh/Desktop/PROBONITE/PROBONITE/packed-PROBONITE/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable multi_baacc"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/multi_baacc.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/multi_baacc.dir/build: multi_baacc
.PHONY : CMakeFiles/multi_baacc.dir/build

CMakeFiles/multi_baacc.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/multi_baacc.dir/cmake_clean.cmake
.PHONY : CMakeFiles/multi_baacc.dir/clean

CMakeFiles/multi_baacc.dir/depend:
	cd /Users/sofianeazogagh/Desktop/PROBONITE/PROBONITE/packed-PROBONITE/src/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/sofianeazogagh/Desktop/PROBONITE/PROBONITE/packed-PROBONITE/src /Users/sofianeazogagh/Desktop/PROBONITE/PROBONITE/packed-PROBONITE/src /Users/sofianeazogagh/Desktop/PROBONITE/PROBONITE/packed-PROBONITE/src/build /Users/sofianeazogagh/Desktop/PROBONITE/PROBONITE/packed-PROBONITE/src/build /Users/sofianeazogagh/Desktop/PROBONITE/PROBONITE/packed-PROBONITE/src/build/CMakeFiles/multi_baacc.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/multi_baacc.dir/depend
