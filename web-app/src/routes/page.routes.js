const express = require('express');
const router = express.Router();
const pageController = require('../controllers/page.controller');

router.get('/', pageController.getHomePage);
router.get('/dashboard', pageController.getDashboardPage);
router.get('/profile', pageController.getProfilePage);
router.get('/search', pageController.getSearchPage);

module.exports = router;
