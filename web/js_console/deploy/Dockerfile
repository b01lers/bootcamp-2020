FROM python:3-alpine

RUN mkdir -p /var/www/js_console/
WORKDIR /var/www/js_console/

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY flag.txt server.py ./
COPY static/ static/
COPY templates templates/

CMD ["python", "./server.py"]
