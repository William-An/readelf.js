make -C ./test/reference_impl;
make -C ./test/test_progs;
./test/reference_impl/readelf_impl ./test/test_progs/helloworld.elf > ./test/ref.out