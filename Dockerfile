FROM public.ecr.aws/sam/emulation-python3.9:latest

LABEL Name="Python Flask Demo App" Version=1.4.3

ARG srcDir=src
WORKDIR /app
COPY $srcDir/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY $srcDir/run.py .
COPY $srcDir/app ./app

EXPOSE 5000

CMD ["gunicorn", "-b", "0.0.0.0:5000", "run:app"]
