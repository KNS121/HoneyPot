FROM python:3.9

WORKDIR /app


COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


COPY . .

RUN mkdir -p /app/python_backend

RUN sed -i "s|directory=\"/app/static\"|directory=\"/app/static/templates\"|g" main.py

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]