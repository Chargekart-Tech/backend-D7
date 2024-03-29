FROM tiangolo/uvicorn-gunicorn-fastapi:python3.11

EXPOSE 80

COPY requirements.txt /app
RUN pip install -r requirements.txt

COPY . /app

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80", "--reload"]
