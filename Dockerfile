FROM python:3.10-alpine

COPY server /server

WORKDIR /server

RUN pip install -r requirements.txt

COPY server/reverb-server.py .

EXPOSE 33333

CMD ["python", "reverb-server.py"]