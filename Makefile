socky.so: clean
	g++ -Wall -fPIC -shared src/main.cpp -o socky.so -ldl -D_GNU_SOURCE

clean:
	rm -rf socky.so