FROM python:3.11.9

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# Flask ke liye correct command
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=8000"]