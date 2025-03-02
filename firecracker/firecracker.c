#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "firecracker.skel.h"

typedef char stringinput[128];
typedef char stringkey[64];

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct firecracker_bpf *skel;
	int err;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <bring_pages (0 or 1)> "
		                "<offsets file (if bring_pages == 1)>\n", argv[0]);
		exit(1);
	}

	int bring_page = atoi(argv[1]);
	if (bring_page != 0 && bring_page != 1) {
		fprintf(stderr, "bring_pages argument must be 0 or 1\n");
		exit(1);
	}

	if (bring_page && argc != 3) {
		fprintf(stderr, "since bring_pages is 1 you should also provide the offsets file\n");
		exit(1);
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = firecracker_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = firecracker_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = firecracker_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! "
	       "Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	stringkey key = "key";
	int init_key = 0;
	err = bpf_map__update_elem(skel->maps.execve_counter, &key, sizeof(key), &init_key, sizeof(init_key),  BPF_ANY);
	if (err != 0) {
		fprintf(stderr, "Failed to save key %d\n", err);
		goto cleanup;
	}

	stringkey bring_page_key = "bring_page";
	err = bpf_map__update_elem(skel->maps.execve_counter, &bring_page_key, sizeof(bring_page_key), &bring_page, sizeof(bring_page),  BPF_ANY);
	if (err != 0) {
		fprintf(stderr, "Failed to save key %d\n", err);
		goto cleanup;
	}

	if (bring_page) {
		FILE *file = fopen(argv[2], "r");
		if (file == NULL) {
			perror("Failed to open offsets file");
			goto cleanup;
		}

		int nr_pages, i = 0;
		if (fscanf(file, "%d", &nr_pages) != 1) {
			printf("Failed to read the number of elements.\n");
			fclose(file);
			goto cleanup;
		}

		err = bpf_map__update_elem(skel->maps.index_map, &i, sizeof(i), &nr_pages, sizeof(nr_pages), BPF_ANY);
		if (err != 0) {
			fprintf(stderr, "Failed to create indexes array err=%d", err);
			goto cleanup;
		}

		for(i = 1; i <= nr_pages; i++) {
			int j;// = i - 1;
			if (fscanf(file, "%d", &j) != 1) {
				printf("Failed to read element %d.\n", i);
				fclose(file);
				goto cleanup;
			}

			err = bpf_map__update_elem(skel->maps.index_map, &i, sizeof(i), &j, sizeof(j), BPF_ANY);
			if (err != 0) {
				fprintf(stderr, "Failed to create indexes array err=%d", err);
				goto cleanup;
			}
		}

		fclose(file);
	}

	for(;;) {
		fprintf(stderr, ".");

//		if (!bring_page) {
			int key_size;
			err = bpf_map__lookup_elem(skel->maps.execve_counter, &key, sizeof(key),  &key_size, sizeof(key_size), BPF_ANY);
			if (err != 0) {
				fprintf(stderr, "Failed to retrieve key_size, err= %d\n", err);
				goto cleanup;
			}
	
			FILE* file = fopen("log.txt", "w");
			if (file == NULL) {
				printf("Failed to open the file.\n");
				goto cleanup;
			}
	
			for (int i=0; i < key_size; i++) {
				stringinput message;
				err = bpf_map__lookup_elem(skel->maps.log_file, &i, sizeof(i), message, sizeof(message), BPF_ANY);
				fprintf(file, "%s\n", message);
			}
	
			fclose(file);
//		}

		sleep(1);
	}

cleanup:
	fprintf(stderr, "cleanup\n");
	firecracker_bpf__destroy(skel);
	return -err;
}
