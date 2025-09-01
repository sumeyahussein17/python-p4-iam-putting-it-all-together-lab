#!/usr/bin/env python3

from random import randint, choice as rc
from faker import Faker

from app import app
from models import db, Recipe, User

fake = Faker()

with app.app_context():

    print("Deleting all records...")
    Recipe.query.delete()
    User.query.delete()

    print("Creating users...")

    users = []
    usernames = []

    for i in range(20):
        username = fake.first_name()
        while username in usernames:
            username = fake.first_name()
        usernames.append(username)

        user = User(
            username=username,
            bio=fake.paragraph(nb_sentences=3),
            image_url=fake.url(),
        )
        # use property setter to hash password
        user.password_hash = username + "password"

        users.append(user)

    db.session.add_all(users)
    db.session.flush()  # ✅ flush so users have IDs before assigning recipes

    print("Creating recipes...")
    recipes = []
    for i in range(100):
        instructions = fake.paragraph(nb_sentences=8)

        # Ensure instructions meet validation (≥ 50 chars)
        while len(instructions) < 50:
            instructions += " " + fake.sentence()

        recipe = Recipe(
            title=fake.sentence(),
            instructions=instructions,
            minutes_to_complete=randint(15, 90),
            user=rc(users)  # ✅ assign user directly
        )

        recipes.append(recipe)

    db.session.add_all(recipes)
    db.session.commit()

    print("✅ Seeding complete!")
