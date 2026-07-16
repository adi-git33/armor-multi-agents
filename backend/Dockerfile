FROM python:3.12-slim

WORKDIR /app

# Headless matplotlib for validation chart export inside the container
ENV MPLBACKEND=Agg \
    PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
