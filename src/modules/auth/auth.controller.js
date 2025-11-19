import authService from "./auth.service.js";

export default {
  register: async (req, res) => {
    try {
      const user = await authService.register(req.body);
      res.json(user);
    } catch (err) {
      res.status(400).json({ message: err.message });
    }
  },

  login: async (req, res) => {
    try {
      const { email, password } = req.body;
      const result = await authService.login({ email, password });

      res.json(result);
    } catch (err) {
      res.status(400).json({ message: err.message });
    }
  },

  refresh: async (req, res) => {
    try {
      const { refreshToken } = req.body;

      const result = await authService.refresh(refreshToken);
      res.json(result);
    } catch (err) {
      res.status(401).json({ message: err.message });
    }
  },
};

