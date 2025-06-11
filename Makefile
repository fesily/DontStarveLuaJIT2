build_from_docker:
	chmod +x tools/build_from_docker.sh
	cd tools && ./build_by_docker.sh docker_build_ubuntu ./docker_mods

build_from_docker_any:
	chmod +x tools/build_from_docker.sh
	cd tools && ./build_by_docker.sh docker_build_ubuntu_any ./docker_mods