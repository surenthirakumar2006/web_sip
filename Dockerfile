FROM python:3.10

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

# Ensure database is created (modify based on your DB setup)
# RUN python -c "import os; os.system('python samp.py db init') if not os.path.exists('app.db') else None"

EXPOSE 1001

CMD ["python", "samp.py"]
