npx ts-node ./test/test.ts > ./test/our.out;
diff ./test/our.out ./test/ref.out;