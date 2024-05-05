

import tensorflow as tf
import numpy as np
import pickle

xy = pickle.load(open("best_moves_xy_native.pickle", "rb"))
assert len(xy) == 5000
data = xy

#x is like (3,4,5,6), with numbers between 0 and 63
#y is like (5,7), with numbers between 0 and 63

# Given dataset
#Extract inputs and outputs
inputs = np.array([inp for inp, _ in data])
outputs = np.array([out for _, out in data])

# One-hot encoding
input_one_hot = tf.keras.utils.to_categorical(inputs, num_classes=64)
output_one_hot_1 = tf.keras.utils.to_categorical(outputs[:, 0], num_classes=64)
output_one_hot_2 = tf.keras.utils.to_categorical(outputs[:, 1], num_classes=64)

# Reshape input to fit the model (flattening the one-hot encoded input tensors)
input_one_hot = input_one_hot.reshape(len(inputs), 4 * 64)

# Define the neural network model
input_layer = tf.keras.Input(shape=(256,))
dense1 = tf.keras.layers.Dense(1024, activation='relu')(input_layer)
dense2 = tf.keras.layers.Dense(256, activation='relu')(dense1)
#dense3 = tf.keras.layers.Dense(256, activation='relu')(dense2)
#dense4 = tf.keras.layers.Dense(256, activation='relu')(dense3)
output_1 = tf.keras.layers.Dense(64, activation='softmax', name='output_1')(dense1)
output_2 = tf.keras.layers.Dense(64, activation='softmax', name='output_2')(dense1)
model = tf.keras.Model(inputs=input_layer, outputs=[output_1, output_2])


# Compile the model with separate metrics for each output
model.compile(
    optimizer='Adam',
    loss='categorical_crossentropy',
    metrics={'output_1': ['accuracy'], 'output_2': ['accuracy']}
)

#callbacks = [StopTrainingAt100Acc()]


# Train the model
history = model.fit(input_one_hot, [output_one_hot_1, output_one_hot_2], epochs=20, batch_size=5)

# Evaluate the model on the training data
accuracy = model.evaluate(input_one_hot, [output_one_hot_1, output_one_hot_2], batch_size=1)

print(accuracy)


#double checking that the inference is 100% on the 5000 samples
#data = [((46, 37, 52, 62),(46, 38))]
for i,(x,y) in enumerate(data): 
     new_data = np.array(x)
     new_data_one_hot = tf.keras.utils.to_categorical(new_data, num_classes=64)
     new_data_one_hot = new_data_one_hot.reshape(1, 4 * 64)
     predictions = model.predict(new_data_one_hot)

     py0 = np.argmax(predictions[0], axis=1)
     py1 = np.argmax(predictions[1], axis=1)
     print("=",i,py0,y[0],py1,y[1])
     assert py0 == y[0]
     assert py1 == y[1]


#import IPython; IPython.embed()


converter = tf.lite.TFLiteConverter.from_keras_model(model)
tflite_model = converter.convert()
with open('model.tflite', 'wb') as f:
     f.write(tflite_model)



