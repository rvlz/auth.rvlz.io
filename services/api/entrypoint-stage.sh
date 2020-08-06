#!/bin/sh

while ! nc -z db 5432; do
  sleep 0.1
done

gunicorn -b 0.0.0.0:5000 wsgi:app
