# Use an official Python runtime as the base image
FROM python:3.9

# Set the working directory in the container
WORKDIR /app

# Copy the requirements.txt file and install the dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Django project code into the container
COPY . .

# Make migrations and migrate the database

RUN python manage.py makemigrations
RUN python manage.py migrate



# Expose the port that Django runs on
EXPOSE 8000

# Run Django's development server when the container starts
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
