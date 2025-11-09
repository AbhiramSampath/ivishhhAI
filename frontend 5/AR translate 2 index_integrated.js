// @ts-nocheck
// This file is now plain JavaScript. Rename to index.js.
import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Image,
  Dimensions,
  Alert, // Used for native alerts in React Native
  Platform, // Used to detect platform (iOS, Android, web)
  ActivityIndicator,
  Animated,
  PanResponder,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context'; // For safe area handling on notched devices
import * as ImagePicker from 'expo-image-picker'; // For accessing device's image library and camera
import { Camera, Search, Image as ImageIcon, Upload, Plus, Volume2, Star } from 'lucide-react-native'; // For icons

// Backend API integration
import { translateCameraImage } from './api/index'; // Import the API function

// Get initial screen dimensions; this will be updated by the Dimensions listener
const { width, height } = Dimensions.get('window');

// Main component for the translation screen
export default function TranslateScreen() {
  const [selectedImage, setSelectedImage] = useState(null); // State for the URI of the selected image
  const [translationData, setTranslationData] = useState(null); // State for translation results
  const [isProcessing, setIsProcessing] = useState(false); // State to indicate if translation is in progress
  const [sourceLanguage, setSourceLanguage] = useState('English'); // State for the source language
  const [targetLanguage, setTargetLanguage] = useState('Hindi'); // State for the target language
  // State to dynamically track screen dimensions for responsive UI
  const [screenData, setScreenData] = useState(Dimensions.get('window'));
  const [isBottomSheetVisible, setIsBottomSheetVisible] = useState(false);
  const [isStarred, setIsStarred] = useState(false);
  const [isMuted, setIsMuted] = useState(false);
  const bottomSheetHeight = 400; // Height of the bottom sheet
  const animatedValue = React.useRef(new Animated.Value(0)).current;
  const pan = React.useRef(new Animated.ValueXY()).current;

  // useEffect hook to listen for screen dimension changes (e.g., device rotation)
  useEffect(() => {
    const subscription = Dimensions.addEventListener('change', ({ window }) => {
      setScreenData(window); // Update screenData state with new dimensions
    });

    // Cleanup function: remove the event listener when the component unmounts
    return () => subscription?.remove();
  }, []); // Empty dependency array ensures this effect runs only once on mount and cleans up on unmount

  // Show bottom sheet when translationData is set
  useEffect(() => {
    if (translationData) {
      setIsBottomSheetVisible(true);
      Animated.timing(animatedValue, {
        toValue: 1,
        duration: 350,
        useNativeDriver: true,
      }).start();
    } else {
      setIsBottomSheetVisible(false);
      Animated.timing(animatedValue, {
        toValue: 0,
        duration: 200,
        useNativeDriver: true,
      }).start();
    }
  }, [translationData]);

  // PanResponder for drag up/down
  const panResponder = PanResponder.create({
    onMoveShouldSetPanResponder: (_, gestureState) => {
      return Math.abs(gestureState.dy) > 10;
    },
    onPanResponderMove: Animated.event([
      null,
      { dy: pan.y },
    ], { useNativeDriver: false }),
    onPanResponderRelease: (_, gesture) => {
      if (gesture.dy > 100) {
        // Dragged down enough, close
        setIsBottomSheetVisible(false);
        setTranslationData(null);
        Animated.timing(animatedValue, {
          toValue: 0,
          duration: 200,
          useNativeDriver: true,
        }).start(() => {
          pan.setValue({ x: 0, y: 0 });
        });
      } else {
        // Snap back up
        Animated.spring(pan.y, {
          toValue: 0,
          useNativeDriver: true,
        }).start();
      }
    },
  });

  // Bottom sheet translateY
  const translateY = Animated.add(
    animatedValue.interpolate({
      inputRange: [0, 1],
      outputRange: [bottomSheetHeight, 0],
    }),
    pan.y
  );

  /**
   * Requests media library permissions for iOS/Android. On web, Expo's ImagePicker
   * typically handles browser-level permissions implicitly when calling `launchImageLibraryAsync`.
   * @returns {Promise<boolean>} Resolves to true if permissions are granted or not applicable (web), false otherwise.
   */
  const requestMediaLibraryPermissions = async () => {
    if (Platform.OS !== 'web') {
      const { status } = await ImagePicker.requestMediaLibraryPermissionsAsync();
      if (status !== 'granted') {
        Alert.alert('Permission required', 'Sorry, we need camera roll permissions to make this work!');
        return false;
      }
    }
    return true;
  };

  /**
   * Opens the device's image library/gallery.
   * Prompts for media library permissions if needed.
   * Sets the selected image URI and clears any existing translation data.
   */
  const pickImage = async () => {
    const hasPermission = await requestMediaLibraryPermissions();
    if (!hasPermission) return; // Exit if permissions are not granted

    const result = await ImagePicker.launchImageLibraryAsync({
      mediaTypes: ImagePicker.MediaTypeOptions.Images, // Only allow image selection
      allowsEditing: true, // Allow user to crop/edit the image
      aspect: [4, 3], // Enforce a 4:3 aspect ratio
      quality: 0.8, // Image compression quality (0-1)
    });

    // If an image was selected (not cancelled) and assets array exists
    if (!result.canceled && result.assets && result.assets[0]) {
      setSelectedImage(result.assets[0].uri); // Set the URI of the selected image
      setTranslationData(null); // Clear previous translation results
    }
  };

  const requestCameraPermissions = async () => {
    if (Platform.OS === 'web') {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({ video: true });
        stream.getTracks().forEach(track => track.stop());
        return true;
      } catch (error) {
        Alert.alert('Camera Access Denied', 'Please allow camera access to take photos.');
        return false;
      }
    }

    const { status } = await ImagePicker.requestCameraPermissionsAsync();
    if (status !== 'granted') {
      Alert.alert('Permission required', 'Sorry, we need camera permissions to make this work!');
      return false;
    }
    return true;
  };

  /**
   * Opens the device's camera to take a new photo.
   * Displays an alert if the camera feature is not supported on the web platform.
   * Prompts for camera permissions if needed.
   * Sets the captured photo's URI and clears any existing translation data.
   */
  const takePhoto = async () => {
    const hasPermission = await requestCameraPermissions();
    if (!hasPermission) return;

    try {
      const result = await ImagePicker.launchCameraAsync({
        allowsEditing: true,
        aspect: [4, 3],
        quality: 0.8,
        cameraType: ImagePicker.CameraType.back,
        presentationStyle: ImagePicker.UIImagePickerPresentationStyle.FULL_SCREEN,
      });

      if (!result.canceled && result.assets && result.assets[0]) {
        setSelectedImage(result.assets[0].uri);
        setTranslationData(null);
      }
    } catch (error) {
      Alert.alert(
        'Camera Error',
        'There was an error accessing the camera. Please try again.'
      );
      console.error('Camera error:', error);
    }
  };

  /**
   * Processes the selected image by sending it to the backend for OCR and translation.
   * Sets `isProcessing` to true during the operation and updates the translation data on success.
   */
  const processImage = async () => {
    if (!selectedImage) {
      Alert.alert('No image selected', 'Please select an image first');
      return;
    }

    setIsProcessing(true); // Start processing, show activity indicator

    try {
      // Prepare form data for the backend API
      const formData = new FormData();

      // Get the image file from the selected URI
      const response = await fetch(selectedImage);
      const blob = await response.blob();

      // Create file object for FormData
      const file = {
        uri: selectedImage,
        type: 'image/jpeg', // Adjust based on actual image type
        name: 'image.jpg',
      };

      formData.append('image', file);
      formData.append('target_lang', targetLanguage.toLowerCase().substring(0, 2)); // e.g., 'hi' for Hindi
      formData.append('source_lang', sourceLanguage.toLowerCase().substring(0, 2)); // e.g., 'en' for English
      formData.append('session_token', 'dummy_session_token'); // Replace with actual session token

      // Call the backend API
      const result = await translateCameraImage(formData);
