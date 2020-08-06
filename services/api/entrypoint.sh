#!/bin/sh

while ! nc -z db 5432; do
  sleep 0.1
done

python manage.py run -h 0.0.0.0
