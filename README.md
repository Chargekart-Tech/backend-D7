# ChargeKart

## Backend Service Codebase

---

Please go to [https://github.com/ChargeKart/services](https://github.com/ChargeKart/services) for instructions on setup and running the service.

----

For checking out the docs for the APIs, please setup and start the service using main docker-compose configuration. The, go to the URL -> 

[http://localhost/api/docs/](http://localhost/api/docs#/)

---

<br/>

## APIs

### **Tag - General**

> Root path - `localhost/api/`

- `/` _[GET]_ -> For checking the running status of the backend.

### **Tag - User**

> Root path - `localhost/api/user/`

- `/login` _[POST]_ -> User Login using `username` and `password`. It sets the authorization cookie.

- `/register` _[POST]_ -> New User Registration using the fields - `username`, `email`, `contact`, `password` and `full_name`. It sets the authorization cookie.

- `/logout` _[POST]_ -> User logout endpoint. Doesn't take any input.

- `/details` _[GET]_ -> Returns user details, based on the authorization cookie. Requires user to be logged in.

- `/change-password` _[POST]_ -> Change currently logged in user password. Takes current password and new password.

### **Tag - Locations**

> Root path - `localhost/api/locations/`

- `/all` _[GET]_ -> 

- `/location/{locid}` _[GET]_ -> 

----

<br/>

## Models

> ### _User_

- username: string - Unique usernamer
- email: string -  Valid email
- contact: string - Valid Phone Number
- full_name: string - Full Name of the user
- password: string - Valid Password (Stored in hashed form in db for security)
- car_number: str
- model_number: str
- model_year: str
- battery_capacity: float

> ### _Location_

- locid: string - Unique id for each location, for ease of access in frontend
- name: string
- latitude: float
- longitude: float
- city: string
- state: string
- country: string
- pincode: int