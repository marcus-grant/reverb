FROM python:3.10-alpine

WORKDIR /server

COPY server/requirements.txt .

RUN pip install -r requirements.txt

COPY server/reverb-server.py .

CMD ["python", "reverb-server.py"]