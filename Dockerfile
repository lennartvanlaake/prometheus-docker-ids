FROM python:2.7.15-alpine3.7
RUN pip install scapy prometheus_client
ADD sniff_exporter.py /
EXPOSE 8000
CMD [ "python", "/sniff_exporter.py" ]