import tensorflow as tf
from tensorflow import keras
from keras.models import load_model
from keras.utils import plot_model
from keras.models import Model
from keras.layers import Input
from keras.layers import Dense
from keras.layers import LSTM
from keras.layers import Dropout
from keras.layers import TimeDistributed
from keras.callbacks import ModelCheckpoint
from keras.callbacks import EarlyStopping
from keras.callbacks import ReduceLROnPlateau
from keras.callbacks import TensorBoard
from keras.callbacks import CSVLogger
from keras.callbacks import LearningRateScheduler
from keras import backend as K
from keras.utils import to_categorical
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix
import numpy as np
import matplotlib.pyplot as plt
import os

# Load the model
model = load_model('model.h5')

# Print model summary
print(model.summary())

# Define the pruning parameters
pruning_params = {
    'pruning_schedule': tfmot.sparsity.keras.PolynomialDecay(
        initial_sparsity=0.0,
        final_sparsity=0.9,
        begin_step=0,
        end_step=1000
    )
}
# Define the pruned model
pruned_model = tfmot.sparsity.keras.prune_low_magnitude(model, **pruning_params)
# Compile the pruned model
pruned_model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
# Train the pruned model
pruned_model.fit(X_train, y_train, epochs=50, batch_size=32, validation_data=(X_test, y_test))
# Save the pruned model
tf.keras.models.save_model(pruned_model, 'pruned_model.h5', include_optimizer=False)