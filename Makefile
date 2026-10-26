.PHONY: up verify load reset-demo down

up:
	docker compose up --build -d --wait

verify: up
	docker compose --profile verify build verify
	docker compose --profile verify run --rm verify

reset-demo:
	docker compose down -v
	docker compose up --build -d --wait
	@echo "Veriler ilk seed haline dondu (simulator birkac saniye icinde seed'i tamamlar)."

down:
	docker compose down