import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_absolute_percentage_error

# Given dataset
data = [1.79, 6.65, 1839.44, 1.31, 1.11, 4.30, 1.52, 1.00, 1.04, 14.54, 2.94, 1.41,
        1.52, 2.98, 3.11, 1.33, 3.49, 1.00, 1.00, 1.81, 25.85, 1.49, 8.32, 4.94,
        1.71, 3.32, 4.16]

# Convert the list to a numpy array
data = np.array(data).reshape(-1, 1)

# Create the input (X) and output (y) variables
X = data[:-1]  # Use all values except the last one as input
y = data[1:]   # Use all values except the first one as output

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Create and train the Linear Regression model
model = LinearRegression()
model.fit(X_train, y_train)

# Predict the next value of x
next_x = model.predict(X_test[-1].reshape(1, -1))

# Calculate the mean absolute percentage error on the testing set
mape = mean_absolute_percentage_error(y_test, model.predict(X_test)) * 100

print("Next value of x:", next_x[0][0])
print("Mean Absolute Percentage Error (MAPE):", mape, "%")
