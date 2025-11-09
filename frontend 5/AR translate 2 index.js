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
   * Simulates an OCR (Optical Character Recognition) and translation process.
   * It sets `isProcessing` to true to show a loading indicator, then after a delay,
   * sets mock translation data and clears the processing state.
   */
  const processImage = async () => {
    if (!selectedImage) {
      Alert.alert('No image selected', 'Please select an image first');
      return;
    }

    setIsProcessing(true); // Start processing, show activity indicator

    // Simulate a network request or heavy processing with a 3-second timeout
    setTimeout(() => {
      const mockTranslation = {
        originalText: 'Attention!\nDangerous cliff\nDo not go near the edge',
        translatedText: 'ध्यान!\nखतरनाक चट्टान\nकिनारे के पास न जाएं',
        sourceLanguage: sourceLanguage, // Use current source language
        targetLanguage: targetLanguage, // Use current target language
      };
      setTranslationData(mockTranslation); // Set the mock translation result
      setIsProcessing(false); // End processing
    }, 3000); // 3-second delay
  };

  /**
   * Swaps the current source and target languages.
   * If there's existing translation data, it also swaps the original and translated texts
   * to align with the new language direction.
   */
  const swapLanguages = () => {
    const temp = sourceLanguage; // Temporarily store the source language
    setSourceLanguage(targetLanguage); // Set source language to the current target
    setTargetLanguage(temp); // Set target language to the original source

    // If translation data exists, update its languages and swap the texts
    if (translationData) {
      setTranslationData({
        originalText: translationData.translatedText, // New original is old translated
        translatedText: translationData.originalText, // New translated is old original
        sourceLanguage: targetLanguage, // Update source language in data
        targetLanguage: temp, // Update target language in data
      });
    }
  };

  // --- Responsive UI Calculations ---
  // Determine if the device is in landscape orientation
  const isLandscape = screenData.width > screenData.height;
  // Simple check to consider if the device is a tablet based on width
  const isTablet = screenData.width > 768;
  // Adjust button size based on tablet detection
  const buttonSize = isTablet ? 72 : 64;
  // Calculate overlay width, limiting it to avoid being too wide on large screens
  const overlayWidth = Math.min(screenData.width * 0.6, 280);

  return (
    // SafeAreaView ensures content is displayed within the safe area boundaries (e.g., below notch)
    <SafeAreaView style={styles.container}>
      <View style={styles.screenBackground}>
        <View style={[styles.imageContainer, { minHeight: screenData.height * (isLandscape ? 0.6 : 0.7) }]}>
          {selectedImage ? (
            // If an image is selected, display it
            <Image source={{ uri: selectedImage }} style={styles.image} resizeMode="cover" />
          ) : (
            // If no image is selected, display the "Upload Image" placeholder.
            // Tapping this directly calls `pickImage` to open the gallery.
            <TouchableOpacity style={styles.placeholderContainer} onPress={pickImage}>
              <View style={styles.uploadArea}>
                <View style={styles.uploadIconContainer}>
                  {/* Upload icon from lucide-react-native */}
                  <Upload size={isTablet ? 60 : 48} color="#4A90E2" />
                  {/* Plus icon from lucide-react-native, positioned relative to Upload icon */}
                  <Plus size={isTablet ? 24 : 20} color="#4A90E2" style={styles.plusIcon} />
                </View>
                <Text style={[styles.placeholderTitle, { fontSize: isTablet ? 20 : 18 }]}>
                  Upload Image
                </Text>
                <Text style={[styles.placeholderText, { fontSize: isTablet ? 16 : 14 }]}>
                  Tap to select an image from your device{'\n'}or take a photo to translate text
                </Text>
                <View style={styles.supportedFormats}>
                  <Text style={styles.formatText}>Supported: JPG, PNG, HEIC</Text>
                </View>
              </View>
            </TouchableOpacity>
          )}
        </View>

        {/* Bottom Controls Area */}
        <View style={[styles.bottomContainer, { paddingHorizontal: isTablet ? 40 : 20 }]}>
          <View style={[styles.controlsRow, isLandscape && styles.controlsRowLandscape]}>
            {/* Camera Button: Left */}
            <TouchableOpacity
              style={[styles.controlButton, { width: buttonSize, height: buttonSize, borderRadius: buttonSize / 2 }]}
              onPress={takePhoto}
            >
              <View style={styles.buttonIcon}>
                <Camera size={isTablet ? 32 : 28} color="#fff" />
              </View>
            </TouchableOpacity>

            {/* Search Button: Center */}
            <TouchableOpacity
              style={[
                styles.controlButton,
                styles.searchButton,
                isProcessing && styles.processingButton,
                { width: 80, height: 80, borderRadius: 40, backgroundColor: '#fff' }
              ]}
              onPress={() => {
                console.log('Search pressed, selectedImage:', selectedImage, 'isProcessing:', isProcessing);
                processImage();
              }}
              disabled={!selectedImage}
            >
              <View style={styles.buttonIcon}>
                {isProcessing ? (
                  <ActivityIndicator size={32} color="#1A1A1A" />
                ) : (
                  <Search size={32} color="#1A1A1A" />
                )}
              </View>
            </TouchableOpacity>

            {/* Custom 'in' Logo Button: Right */}
            <TouchableOpacity
              style={[
                styles.controlButton,
                { width: 60, height: 60, borderRadius: 30, backgroundColor: '#333', justifyContent: 'center', alignItems: 'center' }
              ]}
            >
              <View style={styles.buttonIcon}>
                <Image
                  source={require('./assets/in-logo.png')}
                  style={{ width: 36, height: 36, resizeMode: 'contain' }}
                />
              </View>
            </TouchableOpacity>
          </View>

          {/* Language Selection and Swap Area */}
          <View style={{ flexDirection: 'row', justifyContent: 'center', alignItems: 'center', marginTop: 16, gap: 12 }}>
            {/* English Button */}
            <View style={{ backgroundColor: '#18191C', borderRadius: 16, paddingVertical: 8, paddingHorizontal: 20, minWidth: 90, alignItems: 'center' }}>
              <Text style={{ color: '#fff', fontSize: 23, fontWeight: '500' }}>{sourceLanguage}</Text>
            </View>
            {/* Swap Button */}
            <TouchableOpacity onPress={swapLanguages} style={{ borderRadius: 24, width: 48, height: 48, justifyContent: 'center', alignItems: 'center', marginHorizontal: 8 }}>
              <Image
                source={require('./assets/swap.png')}
                style={{ width: 38, height: 40, resizeMode: 'contain' }}
              />
            </TouchableOpacity>
            {/* Hindi Button */}
            <View style={{ backgroundColor: '#18191C', borderRadius: 16, paddingVertical: 8, paddingHorizontal: 20, minWidth: 90, alignItems: 'center' }}>
              <Text style={{ color: '#fff', fontSize: 23, fontWeight: '500' }}>{targetLanguage}</Text>
            </View>
          </View>
        </View>

        {/* Bottom Sheet Pop-up */}
        {isBottomSheetVisible && (
          <Animated.View
            style={[
              styles.bottomSheet,
              {
                transform: [{ translateY }],
                width: 393,
                position: 'absolute',
                left: 0,
                bottom: 0,
                zIndex: 100,
              },
            ]}
            {...panResponder.panHandlers}
          >
            {/* X Button */}
            <TouchableOpacity onPress={() => { setIsBottomSheetVisible(false); setTranslationData(null); }} style={styles.closeButton}>
              <Text style={{ color: '#fff', fontSize: 24 }}>×</Text>
            </TouchableOpacity>
            {/* Content */}
            <View style={{ flexDirection: 'column', gap: 28, width: '100%' }}>
              <Text style={{ color: '#fff', fontSize: 18, fontWeight: 'bold' }}>Attention</Text>
              <Text style={{ color: '#787878', fontSize: 16 }}>{translationData && translationData.originalText}</Text>
              {/* Star and Speaker after English text */}
              <View style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'flex-start', gap: 16, marginTop: 8 }}>
                {/* Speaker/Mute Icon */}
                <TouchableOpacity onPress={() => setIsMuted(!isMuted)}>
                  <Volume2 size={28} color={isMuted ? '#787878' : '#fff'} />
                </TouchableOpacity>
                {/* Star Icon */}
                <TouchableOpacity onPress={() => setIsStarred(!isStarred)}>
                  <Star size={28} color={isStarred ? '#fff' : '#787878'} fill={isStarred ? '#fff' : 'none'} />
                </TouchableOpacity>
              </View>
              <Text style={{ color: '#fff', fontSize: 20, fontWeight: 'bold' }}>{translationData && translationData.translatedText}</Text>
            </View>
            {/* Star and Speaker at the bottom left */}
            <View style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'flex-start', width: '100%', marginTop: 24, gap: 16 }}>
              {/* Speaker/Mute Icon */}
              <TouchableOpacity onPress={() => setIsMuted(!isMuted)} style={{ width: 28, height: 28, justifyContent: 'center', alignItems: 'center' }}>
                <Volume2 size={28} color={isMuted ? '#787878' : '#fff'} />
              </TouchableOpacity>
              {/* Star Icon */}
              <TouchableOpacity onPress={() => setIsStarred(!isStarred)} style={{ width: 28, height: 28, justifyContent: 'center', alignItems: 'center' }}>
                <Star size={28} color={isStarred ? '#fff' : '#787878'} fill={isStarred ? '#fff' : 'none'} />
              </TouchableOpacity>
              {/* Placeholder for third icon to keep spacing and size consistent */}
              <View style={{ width: 28, height: 28, justifyContent: 'center', alignItems: 'center' }} />
            </View>
          </Animated.View>
        )}
      </View>
    </SafeAreaView>
  );
}

// StyleSheet for component styling
const styles = StyleSheet.create({
  container: {
    flex: 1, // Makes the container take up the full available screen space
    backgroundColor: '#000', // Solid black background
  },
  screenBackground: {
    flex: 1,
    borderRadius: 20,
    overflow: 'hidden',
    backgroundColor: 'lightgray',
    // Replace '../assets/bg.png' with your actual image path
    backgroundImage: `url('../assets/bg.png')`,
    backgroundRepeat: 'no-repeat',
    backgroundPosition: '-83.585px -165.675px',
    backgroundSize: '142.791% 141.709%',
  },
  imageContainer: {
    flex: 1, // This view will take up the remaining space after the bottom controls
    position: 'relative', // Allows for absolute positioning of child elements (like the text overlay)
  },
  image: {
    width: '100%', // Image takes full width of its container
    height: '100%', // Image takes full height of its container
    borderTopLeftRadius: 24, // Curved top left edge
    borderTopRightRadius: 24, // Curved top right edge
    borderBottomLeftRadius: 0, // Square bottom left edge
    borderBottomRightRadius: 0, // Square bottom right edge
  },
  placeholderContainer: {
    flex: 1, // Placeholder fills its container
    justifyContent: 'center', // Centers children vertically
    alignItems: 'center', // Centers children horizontally
    backgroundColor: '#111', // Dark grey background for the placeholder area
    padding: 20, // Padding around the content inside the placeholder
  },
  uploadArea: {
    alignItems: 'center', // Centers items horizontally
    justifyContent: 'center', // Centers items vertically
    borderWidth: 2, // Border for the upload box
    borderColor: '#4A90E2', // Blue border color
    borderStyle: 'dashed', // Dashed border style
    borderRadius: 16, // Rounded corners for the upload box
    padding: 40, // Inner padding for the upload box
    backgroundColor: 'rgba(74, 144, 226, 0.05)', // Semi-transparent blue background
    minWidth: '80%', // Minimum width of the upload box
    maxWidth: 400, // Maximum width to prevent it from getting too wide on large screens
  },
  uploadIconContainer: {
    position: 'relative', // Allows positioning of the plus icon relative to this container
    marginBottom: 16, // Space below the upload icon
  },
  plusIcon: {
    position: 'absolute', // Positions the plus icon absolutely
    bottom: -8, // Offset from the bottom of its parent
    right: -8, // Offset from the right of its parent
    backgroundColor: '#000', // Black background for the small plus circle
    borderRadius: 12, // Makes the plus icon's background circular
    padding: 2, // Padding inside the plus icon's background
  },
  placeholderTitle: {
    color: '#4A90E2', // Blue text color for the title
    fontWeight: 'bold', // Bold font weight
    marginBottom: 8, // Space below the title
    textAlign: 'center', // Centers the title text
  },
  placeholderText: {
    color: '#666', // Grey text color for descriptive text
    textAlign: 'center', // Centers the descriptive text
    lineHeight: 20, // Line height for better readability
    marginBottom: 16, // Space below the descriptive text
  },
  supportedFormats: {
    paddingHorizontal: 12, // Horizontal padding
    paddingVertical: 6, // Vertical padding
    backgroundColor: 'rgba(255, 255, 255, 0.1)', // Semi-transparent white background
    borderRadius: 8, // Rounded corners
  },
  formatText: {
    color: '#888', // Lighter grey text color
    fontSize: 12, // Smaller font size
    textAlign: 'center', // Centers the format text
  },
  textOverlay: {
    position: 'absolute', // Positioned absolutely over the image
    top: '35%', // Position from the top of the image container
  },
  textBox: {
    backgroundColor: 'rgba(0, 100, 100, 0.95)', // Dark teal background with high opacity
    padding: 16, // Padding inside the text box
    borderRadius: 8, // Rounded corners for the text box
    alignItems: 'center', // Centers content horizontally within the text box
    borderWidth: 2, // Border around the text box
    borderColor: 'rgba(255, 255, 255, 0.3)', // Semi-transparent white border
    shadowColor: '#000', // Black shadow
    shadowOffset: { width: 0, height: 4 }, // Shadow offset (x, y)
    shadowOpacity: 0.3, // Shadow opacity
    shadowRadius: 8, // Shadow blur radius
    elevation: 8, // Android specific shadow property
  },
  warningIcon: {
    marginBottom: 8, // Space below the warning icon
  },
  warningSymbol: {
    fontSize: 24, // Size of the warning emoji
    color: '#FFD700', // Gold color for the warning
  },
  overlayTitle: {
    color: '#fff', // White text color
    fontSize: 18, // Font size for the overlay title
    fontWeight: 'bold', // Bold font weight
    textAlign: 'center', // Centers the title text
    marginBottom: 8, // Space below the title
  },
  overlayText: {
    color: '#fff', // White text color
    fontSize: 14, // Font size for the main overlay text
    textAlign: 'center', // Centers the main text
    fontWeight: '500', // Medium font weight
    lineHeight: 18, // Line height for readability
    marginBottom: 8, // Space below the main text
  },
  overlaySubtext: {
    color: '#E0E0E0', // Light grey text color
    fontSize: 12, // Smaller font size for subtext
    textAlign: 'center', // Centers the subtext
    lineHeight: 16, // Line height
    fontStyle: 'italic', // Italic style for subtext
  },
  bottomContainer: {
    backgroundColor: '#000', // Black background for bottom controls
    paddingBottom: Platform.OS === 'web' ? 20 : 40, // Responsive padding for web vs native
    paddingTop: 20, // Top padding for controls area
  },
  controlsRow: {
    flexDirection: 'row', // Arrange buttons horizontally
    justifyContent: 'space-around', // Distribute space evenly around buttons
    alignItems: 'center', // Align buttons vertically in the center
    marginBottom: 24, // Space below the control row
  },
  controlsRowLandscape: {
    marginBottom: 16, // Less margin in landscape mode
  },
  controlButton: {
    backgroundColor: '#333', // Dark grey background for control buttons
    justifyContent: 'center', // Centers content horizontally
    alignItems: 'center', // Centers content vertically
    elevation: 4, // Android shadow
    shadowColor: '#000', // iOS shadow color
    shadowOffset: { width: 0, height: 2 }, // iOS shadow offset
    shadowOpacity: 0.3, // iOS shadow opacity
    shadowRadius: 4, // iOS shadow blur radius
  },
  searchButton: {
    backgroundColor: '#4A90E2', // Blue background for the search/process button
  },
  processingButton: {
    backgroundColor: '#6BA3E8', // Lighter blue when the button is in a processing state
  },
  buttonIcon: {
    justifyContent: 'center', // Centers icon horizontally
    alignItems: 'center', // Centers icon vertically
  },
  languageContainer: {
    flexDirection: 'row', // Arrange language elements horizontally
    justifyContent: 'center', // Centers content horizontally
    alignItems: 'center', // Aligns content vertically in the center
    paddingTop: 8, // Top padding
  },
  languageContainerLandscape: {
    paddingTop: 4, // Less padding in landscape mode
  },
  languageText: {
    color: '#fff', // White text color for language display
    fontWeight: '500', // Medium font weight
  },
  swapButton: {
    marginHorizontal: 24, // Horizontal margin around the swap button
    padding: 8, // Padding inside the swap button
  },
  bottomSheet: {
    backgroundColor: '#000',
    borderTopLeftRadius: 20,
    borderTopRightRadius: 20,
    padding: 20,
  },
  closeButton: {
    alignItems: 'flex-end',
  },
});
