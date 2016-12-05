# FSND-Item-Catalog
## Project for Udacity Fullstack NanoDegree

This is my submission for the fourth project in the Fullstack NanoDegree. The assignment was to create an item catalog where different users can register and add, edit and delete items into a central database. I decided to make the beginning of a "shared library" application where people could keep track of what books they own by which authors. User authentication is handled by either Google OAuth or Facebook login. 

Technologies used: Flask, SQLAlchemy, Bootstrap
Site includes JSON endpoints

## Running the program

In order to run the code, you must have the latest Vagrant build as detailed in the [Udacity project notes] (https://docs.google.com/document/d/16IgOm4XprTaKxAa8w02y028oBECOoB1EI1ReddADEeY/pub?embedded=true).

1. Fork the [Fullstack Nanodegree Repository] (https://github.com/udacity/fullstack-nanodegree-vm), clone it to your local machine and run the Vagrant VM. 
2. Use the command `vagrant up` to start the VM followed by `vagrant ssh` to log in. 
3. `python library_database_setup.py` to set up the database
4. Then `python libraryproject.py` to start the site
5. Point your browser to localhost:5000 

### Database structure

The shared library is arranged by authors. First add an author (first name and last name). Then one can add books to the author. Books have titles, descriptions, genres, page counts, and publication year. 

## Next steps

In order to make this a truly "shared library" I need to add a way for people to claim which books they own, and to be able to "check out" books from each other. Include due dates, list books that are unavailable, etc. 





