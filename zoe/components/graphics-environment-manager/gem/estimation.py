from .measurement import _numpy


MAX_DIMENSION = 64


def _array(value, name, shape=None):
    np = _numpy()
    try:
        result = np.asarray(value, dtype=np.float64)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} must contain real numbers") from error
    if shape is not None and result.shape != shape:
        raise ValueError(f"{name} must have shape {shape}")
    if not np.all(np.isfinite(result)):
        raise ValueError(f"{name} must contain only finite values")
    return result


def _covariance(value, name, dimension):
    np = _numpy()
    result = _array(value, name, (dimension, dimension))
    if not np.allclose(result, result.T, rtol=0, atol=1e-10):
        raise ValueError(f"{name} must be symmetric")
    if np.linalg.eigvalsh(result).min() < -1e-10:
        raise ValueError(f"{name} must be positive semidefinite")
    return result


class ExtendedKalmanFilter:
    def __init__(self, initial_state, initial_covariance, process_model=None, measurement_model=None):
        self.state = _array(initial_state, "initial_state").reshape(-1)
        if not 1 <= len(self.state) <= MAX_DIMENSION:
            raise ValueError(f"state dimension must be between 1 and {MAX_DIMENSION}")
        self.covariance = _covariance(initial_covariance, "initial_covariance", len(self.state))
        if process_model is not None and not callable(process_model):
            raise ValueError("process_model must be callable")
        if measurement_model is not None and not callable(measurement_model):
            raise ValueError("measurement_model must be callable")
        self.process_model = process_model
        self.measurement_model = measurement_model

    def predict(self, process_matrix=None, process_covariance=None, control_matrix=None, control=None):
        np = _numpy()
        dimension = len(self.state)
        if self.process_model is not None:
            next_state, process_matrix = self.process_model(self.state.copy())
            next_state = _array(next_state, "process next state", (dimension,))
        else:
            process_matrix = _array(process_matrix, "process_matrix", (dimension, dimension))
            next_state = process_matrix @ self.state
        process_matrix = _array(process_matrix, "process_matrix", (dimension, dimension))
        if control_matrix is not None:
            control_matrix = _array(control_matrix, "control_matrix")
            if control_matrix.ndim != 2 or control_matrix.shape[0] != dimension:
                raise ValueError("control_matrix must have the state dimension in its first axis")
            control = _array(control, "control", (control_matrix.shape[1],))
            next_state = next_state + control_matrix @ control
        process_covariance = _covariance(process_covariance, "process_covariance", dimension)
        covariance = process_matrix @ self.covariance @ process_matrix.T + process_covariance
        self.state = _array(next_state, "process next state", (dimension,))
        self.covariance = _covariance(covariance, "predicted covariance", dimension)
        return self.state.copy(), self.covariance.copy()

    def update(self, observation, observation_matrix=None, observation_covariance=None):
        np = _numpy()
        dimension = len(self.state)
        if self.measurement_model is not None:
            expected, observation_matrix = self.measurement_model(self.state.copy())
        else:
            observation_matrix = _array(observation_matrix, "observation_matrix")
            expected = observation_matrix @ self.state
        observation_matrix = _array(observation_matrix, "observation_matrix")
        if observation_matrix.ndim != 2 or observation_matrix.shape[1] != dimension:
            raise ValueError("observation_matrix must have the state dimension in its second axis")
        measurement_dimension = observation_matrix.shape[0]
        if not 1 <= measurement_dimension <= MAX_DIMENSION:
            raise ValueError(f"observation dimension must be between 1 and {MAX_DIMENSION}")
        expected = _array(expected, "expected observation", (measurement_dimension,))
        observation = _array(observation, "observation", (measurement_dimension,))
        observation_covariance = _covariance(observation_covariance, "observation_covariance", measurement_dimension)
        innovation = observation - expected
        predicted_covariance = self.covariance
        innovation_covariance = observation_matrix @ predicted_covariance @ observation_matrix.T + observation_covariance
        try:
            gain = np.linalg.solve(
                innovation_covariance,
                (predicted_covariance @ observation_matrix.T).T,
            ).T
        except np.linalg.LinAlgError as error:
            raise ValueError("innovation covariance is singular") from error
        self.state = self.state + gain @ innovation
        identity = np.eye(dimension)
        residual = identity - gain @ observation_matrix
        self.covariance = _covariance(
            residual @ predicted_covariance @ residual.T + gain @ observation_covariance @ gain.T,
            "updated covariance", len(self.state),
        )
        return {
            "state": self.state.copy(),
            "covariance": self.covariance.copy(),
            "innovation": innovation,
            "innovation_covariance": innovation_covariance,
            "kalman_gain": gain,
        }


def linear_filter(observations, process_matrix, process_covariance, observation_matrix,
                  observation_covariance, initial_state, initial_covariance,
                  control_matrix=None, controls=None):
    estimator = ExtendedKalmanFilter(initial_state, initial_covariance)
    observations = list(observations)
    if not observations:
        raise ValueError("at least one observation is required")
    if control_matrix is not None and controls is None:
        raise ValueError("controls are required when control_matrix is supplied")
    if controls is not None and len(controls) != len(observations):
        raise ValueError("controls and observations must have matching lengths")
    results = []
    for index, observation in enumerate(observations):
        control = controls[index] if controls is not None else None
        predicted_state, predicted_covariance = estimator.predict(
            process_matrix, process_covariance, control_matrix, control,
        )
        update = estimator.update(observation, observation_matrix, observation_covariance)
        results.append({
            "index": index,
            "predicted_state": predicted_state.tolist(),
            "predicted_covariance": predicted_covariance.tolist(),
            "state": update["state"].tolist(),
            "covariance": update["covariance"].tolist(),
            "innovation": update["innovation"].tolist(),
            "innovation_covariance": update["innovation_covariance"].tolist(),
            "kalman_gain": update["kalman_gain"].tolist(),
        })
    return results
