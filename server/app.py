#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe


# ----------------------------
# AUTH ROUTES
# ----------------------------

class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
        bio = data.get("bio", "")
        image_url = data.get("image_url", "")

        if not username or not password:
            return {"error": "Username and password required"}, 422

        try:
            user = User(username=username, bio=bio, image_url=image_url)
            user.password_hash = password  # triggers setter
            db.session.add(user)
            db.session.commit()

            # log them in
            session["user_id"] = user.id
            return user.to_dict(), 201

        except IntegrityError:
            db.session.rollback()
            return {"error": "Username already exists"}, 422


class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "Unauthorized"}, 401

        user = User.query.get(user_id)
        if not user:
            return {"error": "Unauthorized"}, 401

        return user.to_dict(), 200


class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        user = User.query.filter_by(username=username).first()
        if user and user.authenticate(password):
            session["user_id"] = user.id
            return user.to_dict(), 200

        return {"error": "Invalid username or password"}, 401


class Logout(Resource):
    def delete(self):
        session["user_id"] = None
        return {}, 204


# ----------------------------
# RECIPES
# ----------------------------

class RecipeIndex(Resource):
    def get(self):
        # public route
        recipes = Recipe.query.all()
        return [r.to_dict() for r in recipes], 200

    def post(self):
        # must be logged in
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "Unauthorized"}, 401

        data = request.get_json()
        title = data.get("title")
        instructions = data.get("instructions")
        minutes_to_complete = data.get("minutes_to_complete")

        if not title or not instructions:
            return {"error": "Title and instructions required"}, 422

        recipe = Recipe(
            title=title,
            instructions=instructions,
            minutes_to_complete=minutes_to_complete,
            user_id=user_id,
        )

        db.session.add(recipe)
        db.session.commit()

        return recipe.to_dict(), 201


# ----------------------------
# REGISTER ROUTES
# ----------------------------

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
