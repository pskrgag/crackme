#include <stdio.h>

int main(void)
{
	char data[500];

	printf("Enter txt: ");
	fgets(data, sizeof(data), stdin);
	_Exit(10);
}
