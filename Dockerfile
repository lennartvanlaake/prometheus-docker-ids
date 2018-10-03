FROM python:2.7.15-alpine3.7
RUN pip install scapy prometheus_client requests
ADD sniff_exporter.py /
EXPOSE 6789
CMD [ "python", "/sniff_exporter.py" ]