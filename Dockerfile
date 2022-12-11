FROM python:3.10-alpine

COPY requirements.txt /requirements.txt

RUN pip install -r /requirements.txt

COPY reverb.py /app/reverb.py
WORKDIR /app

CMD /app/reverb.py serve