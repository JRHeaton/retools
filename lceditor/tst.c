#include <stdio.h>
#include <stdlib.h>
void hello(void) {
	char *env = getenv("MYSTUFF");
	if (env) {
		printf("MYSTUFF : %s\n",env);
	} else {
		puts("hello world");
	}
}
int main() {
	hello();
	puts("bye");
}
