FROM python:3.9-slim

RUN pip install cortexutils pywinrm

COPY MimikatzResponder.py /opt/MimikatzResponder.py

ENTRYPOINT ["python3", "/opt/MimikatzResponder.py"]

