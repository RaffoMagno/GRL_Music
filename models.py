from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def get_id(self):
        return self.username

    @classmethod
    def get(cls, username):
        from app import mongo  
        user_data = mongo.db.users.find_one({"username": username})
        if user_data:
            return cls(user_data["username"], user_data["password"])
        return None




