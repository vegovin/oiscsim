/**
   oiscsim - One Instruction Set Computer Simulator
    Copyright (C) 2015 Venkatraman Govindaraju

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <malloc.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>



void usage(const char *name, struct option *options, unsigned num_options);
void load_and_simulate(const char *binname);

int main(int argc, char *argv[])
{
  static struct option options[] = {
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
  };

  int c, optidx = 0;

  // parse_args(argc, argv);
  while ((c = getopt_long(argc, argv, "h", options, &optidx)) != -1) {
    switch (c) {
    default:
    case 0: break;
    case 'h': usage(argv[0], options, sizeof(options)/sizeof(options[0])-1);
    }
  }
  if (argc != optind+1) {
    usage(argv[0], options, sizeof(options)/sizeof(options[0])-1);
  }
  load_and_simulate(argv[optind]);
  return 0;
}


void usage(const char *name,
	   struct option *options, unsigned num_options)
{
  int i;
  printf("Usage: %s [options] <binary>\n", name);
  printf("Options:\n");
  for (i = 0; i < num_options; ++i) {
    printf(" --%s", options[i].name);
    switch (options[i].has_arg) {
    default:
    case no_argument:  break;
    case optional_argument: printf("[=arg]"); break;
    case required_argument: printf("=arg"); break;
    }
    printf("\n");
  }
  exit(0);
}

void load_and_simulate(const char *bin_fname)
{
  // Load binary into memory
  int fd = open(bin_fname, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "Cannot open file %s\n", bin_fname);
    exit(-1);
  }
  size_t len = lseek(fd, 0, SEEK_END);
  void *data = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
  if (data == MAP_FAILED) {
    fprintf(stderr, "Memory map failed\n");
    close(fd);
    exit(-1);
  }

  // FIXME:: How big is our memory?? -- 512MB
  // FIXME:: What is the format of binary? ELF?? -- Just full mem-image
  // FIXME:: where is the program start address -- at 0x0
  // FIXME:: Where to load the binary -- at 0x0
  const size_t mem_size = ((size_t)512)*1024*1024;
  const size_t load_pos = (size_t)0x0;
  const size_t start_pos = (size_t)0x0;

  int32_t *mem = (int32_t*)memalign(4096, mem_size);

  if (!mem) {
    fprintf(stderr, "Cannot allocate memory\n");
    munmap(data, len);
    close(fd);
    exit(-1);
  }
  // Load data to 0x1000
  memcpy(&mem[load_pos], data, len);

  munmap(data, len);
  close(fd);

#define VALID_MEM(X) \
  ((X) >= 0 && (X) <= (mem_size - sizeof(int32_t)))
#define VALID_PC(X) \
  ((X) >= 0 && (X) <= (mem_size - sizeof(int32_t)*3))
  // Start executing --
  // All our instructions are subleq A, B, C
  // From wikipedia: https://en.wikipedia.org/wiki/One_instruction_set_computer
  // subleq A, B, C: Mem[B] = Mem[B] - Mem[A]
  //                 if (Mem[B] <= 0) goto C
  int32_t pc = (int32_t)start_pos;
  while (VALID_PC(pc)) {
    int32_t A = mem[pc];
    int32_t B = mem[pc+1];
    int32_t C = mem[pc+2];
    printf("%8x: %8x %8x %8x: A=%d B=%d\n",pc, A, B, C,
           VALID_MEM(A)?mem[A]:0, VALID_MEM(B)?mem[B]:0);

    if (A < 0 || B < 0) {
      pc = 0;
      continue;
    }
    mem[B] -= mem[A];
    if (mem[B] > 0) {
      pc += 3;
    } else {
      pc = C;
    }
  }

  // clean up
  free(mem);
}
