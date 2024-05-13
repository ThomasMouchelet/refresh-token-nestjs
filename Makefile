.PHONY: up
up:	
	docker-compose -f docker-compose-dev.yml up -d

.PHONY: network
network:	
	docker network create theseus-network

.PHONY: down
down:
	docker stop api-meeting
	docker rm api-meeting
	docker rmi api-meeting
	

.PHONY: reset
reset:
	docker system prune -a -f
	docker volume prune -f
	docker network prune -f

.PHONY: dev
dev: network up