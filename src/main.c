#include "utils/main_utils.h"
#include "utils/utils.h"

int main(int argc, char* argv[])
{
	main_args_t* args = parse_args(argc, argv);
	if (!args)
	{
		show_message(1, "Failed to parse command line arguments.");
		return 1;
	}

	if (args->encrypt)
		encrypt_mode(args);
	else
		decrypt_mode(args);

	free(args->ctx);
	free(args);

	return 0;
}