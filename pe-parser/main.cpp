#include "printa/printa.hpp"
#include "utils.h"

int main(int argc, char* argv[])
{
	utils utils(argv[1]);

	utils.pe_parser();

	return 0;
}