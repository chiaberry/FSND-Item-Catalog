import sys

from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.sql import func

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'
    name = Column(String(30), nullable=False)
    id = Column(Integer, primary_key=True)
    email = Column(String(250))
    picture = Column(String(250))


class Author(Base):
    __tablename__ = 'author'
    lastName = Column(String(80), nullable=False)
    firstName = Column(String(80))
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    create_date = Column(DateTime, default=func.now())
    last_mod = Column(DateTime, onupdate=func.now())

    @property
    def serialize(self):
        return {
            'last_name': self.lastName,
            'first_name': self.firstName,
            'id': self.id,
            'user_id': self.user_id,
        }


class Book(Base):
    __tablename__ = 'book'
    title = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(450))
    genre = Column(String(80))
    page_count = Column(Integer)
    year = Column(Integer)
    author_id = Column(Integer, ForeignKey('author.id'))
    author = relationship(Author)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    create_date = Column(DateTime, default=func.now())
    last_mod = Column(DateTime, onupdate=func.now())

    @property
    def serialize(self):
        return {
            'title': self.title,
            'description': self.description,
            'id': self.id,
            'genre': self.genre,
            'page_count': self.page_count,
            'year': self.year,
        }


engine = create_engine('sqlite:///librarydatabase.db')

Base.metadata.create_all(engine)
