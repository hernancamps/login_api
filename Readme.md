Challenge 
---------------------------------------

How to set up my environment
---------------------------------------
Please be aware that this instructions may be vary depending on your
environment. This was done in a Ubuntu OS.

Before starting clone the repository and go to the root of the cloned repository.

Create an environment, I did this by running:

```bash
python3 -m venv venv
```

And then activate it by running:

```bash
source venv/bin/activate
```

Install dependencies
---------------------------------------
Make sure that the environment is activated and then run the following command
to install dependencies:

```bash
pip install -r requirements.txt
```

Run
---------------------------------------

You are all set, if you want to run the app use:

```bash
python api.py
```

Please be aware
---------------------------------------
The app will run in a flask development server with debugging activated.
