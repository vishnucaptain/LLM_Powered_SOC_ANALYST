from fastapi import FastAPI

app=FastAPI()

@app.get("/predict")

def predict():

    return {'message':'This is a prediction number or an endpoint for the prediction model and the model will be trained and tested well'}