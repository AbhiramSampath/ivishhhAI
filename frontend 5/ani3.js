import React, { useState, useEffect, useRef, useCallback } from 'react';
import * as Google from 'expo-auth-session/providers/google';
import * as WebBrowser from 'expo-web-browser';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { Alert } from 'react-native';
import { useNavigation } from '@react-navigation/native';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  Dimensions,
  StatusBar,
  Image,
  KeyboardAvoidingView,
  Platform,
  Animated,
  Easing,
} from 'react-native';

const { width, height } = Dimensions.get('window');
const { width: screenWidth } = Dimensions.get('window');
const CombinedScreen = () => {
  // Animation state
  const [showLogin, setShowLogin] = useState(false);
  
  // Login form states
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isEmailFocused, setIsEmailFocused] = useState(false);
  const [isPasswordFocused, setIsPasswordFocused] = useState(false);
  const [isButtonPressed, setIsButtonPressed] = useState(false);
  const [isGoogleButtonPressed, setIsGoogleButtonPressed] = useState(false);
  const [isFacebookButtonPressed, setIsFacebookButtonPressed] = useState(false);

  // Animation refs
  const topImageAnim = useRef(new Animated.Value(0)).current;
  const rightImageAnim = useRef(new Animated.Value(0)).current;
  const bottomImageAnim = useRef(new Animated.Value(0)).current;
  const leftImageAnim = useRef(new Animated.Value(0)).current;
  const imagesVisibilityAnim = useRef(new Animated.Value(1)).current;
  const diamond1Anim = useRef(new Animated.Value(0)).current;
  const diamond2Anim = useRef(new Animated.Value(0)).current;
  const diamond3Anim = useRef(new Animated.Value(0)).current;
  const diamond4Anim = useRef(new Animated.Value(0)).current;
  const logoScaleAnim = useRef(new Animated.Value(0)).current;
  const textAnim = useRef(new Animated.Value(0)).current;
  const colorChangeAnim = useRef(new Animated.Value(0)).current;
  const colorChangeAnimJS = useRef(new Animated.Value(0)).current;
  const loginFadeAnim = useRef(new Animated.Value(0)).current;
  const animationContainerAnim = useRef(new Animated.Value(1)).current;
  const loginScaleAnim = useRef(new Animated.Value(0.95)).current;
  const loginBlurAnim = useRef(new Animated.Value(1)).current;

  // Memoize the animation sequence function with performance optimizations
  const animateSequence = useCallback(() => {
    // Reset all animations
    topImageAnim.setValue(0);
    rightImageAnim.setValue(0);
    bottomImageAnim.setValue(0);
    leftImageAnim.setValue(0);
    imagesVisibilityAnim.setValue(1);
    diamond1Anim.setValue(0);
    diamond2Anim.setValue(0);
    diamond3Anim.setValue(0);
    diamond4Anim.setValue(0);
    logoScaleAnim.setValue(0);
    textAnim.setValue(0);
    colorChangeAnim.setValue(0);
    loginFadeAnim.setValue(0);
    animationContainerAnim.setValue(1);
    loginScaleAnim.setValue(0.95);
    loginBlurAnim.setValue(1);

    // Optimized animation sequence with corrected easing
    Animated.sequence([
      // Smoother parallel images animation - DURATION INCREASED AGAIN HERE
      // CHANGED FROM Animated.stagger TO Animated.parallel HERE
      Animated.parallel([
        Animated.timing(topImageAnim, {
          toValue: 1,
          duration: 1000, // Increased duration to 1 second
          useNativeDriver: true,
          easing: Easing.out(Easing.cubic),
        }),
        Animated.timing(rightImageAnim, {
          toValue: 1,
          duration: 1000, // Increased duration to 1 second
          useNativeDriver: true,
          easing: Easing.out(Easing.cubic),
        }),
        Animated.timing(bottomImageAnim, {
          toValue: 1,
          duration: 1000, // Increased duration to 1 second
          useNativeDriver: true,
          easing: Easing.out(Easing.cubic),
        }),
        Animated.timing(leftImageAnim, {
          toValue: 1,
          duration: 1000, // Increased duration to 1 second
          useNativeDriver: true,
          easing: Easing.out(Easing.cubic),
        }),
      ]),
      // Reduced wait time
      Animated.delay(300),
      // Smoother vanish effect
      Animated.timing(imagesVisibilityAnim, {
        toValue: 0,
        duration: 250,
        useNativeDriver: true,
        easing: Easing.in(Easing.ease),
      }),
      // Reduced delay
      Animated.delay(150),
      // Optimized diamond animations with stagger
      Animated.stagger(100, [
        Animated.timing(diamond1Anim, {
          toValue: 1,
          duration: 600,
          useNativeDriver: true,
          easing: Easing.out(Easing.back(1.2)),
        }),
        Animated.timing(diamond2Anim, {
          toValue: 1,
          duration: 600,
          useNativeDriver: true,
          easing: Easing.out(Easing.back(1.2)),
        }),
        Animated.timing(diamond3Anim, {
          toValue: 1,
          duration: 600,
          useNativeDriver: true,
          easing: Easing.out(Easing.back(1.2)),
        }),
        Animated.timing(diamond4Anim, {
          toValue: 1,
          duration: 600,
          useNativeDriver: true,
          easing: Easing.out(Easing.back(1.2)),
        }),
      ]),
      // Overlapped logo scale with diamonds
      Animated.delay(-200),
      Animated.spring(logoScaleAnim, {
        toValue: 1,
        tension: 120,
        friction: 7,
        useNativeDriver: true,
      }),
      // Overlapped text animation
      Animated.delay(-100),
      Animated.timing(textAnim, {
        toValue: 1,
        duration: 500,
        useNativeDriver: true,
        easing: Easing.out(Easing.ease),
      }),
      // Overlapped color change
      Animated.delay(-200),
      Animated.timing(colorChangeAnimJS, {
        toValue: 1,
        duration: 600,
        useNativeDriver: false,
        easing: Easing.inOut(Easing.ease),
      }),
      // Reduced wait before login
      Animated.delay(600),
      // Smoother login transition
      Animated.parallel([
        Animated.timing(animationContainerAnim, {
          toValue: 0,
          duration: 500,
          useNativeDriver: true,
          easing: Easing.inOut(Easing.ease),
        }),
        Animated.timing(loginFadeAnim, {
          toValue: 1,
          duration: 500,
          useNativeDriver: true,
          easing: Easing.out(Easing.ease),
        }),
        Animated.timing(loginScaleAnim, {
          toValue: 1,
          duration: 500,
          useNativeDriver: true,
          easing: Easing.out(Easing.back(1.1)),
        }),
        Animated.timing(loginBlurAnim, {
          toValue: 0,
          duration: 500,
          useNativeDriver: true,
          easing: Easing.out(Easing.ease),
        }),
      ]),
    ]).start(() => {
      setShowLogin(true);
    });
  }, [
    topImageAnim,
    rightImageAnim,
    bottomImageAnim,
    leftImageAnim,
    imagesVisibilityAnim,
    diamond1Anim,
    diamond2Anim,
    diamond3Anim,
    diamond4Anim,
    logoScaleAnim,
    textAnim,
    colorChangeAnim,
    loginFadeAnim,
    animationContainerAnim,
    loginScaleAnim,
    loginBlurAnim,
  ]);

  useEffect(() => {
    animateSequence();
  }, [animateSequence]);

  // Professional transition interpolations with smoother curves
  const subtleScale = loginScaleAnim.interpolate({
    inputRange: [0.95, 1],
    outputRange: [0.95, 1],
    extrapolate: 'clamp',
  });

  const blurOpacity = loginBlurAnim.interpolate({
    inputRange: [0, 1],
    outputRange: [0, 0.3],
    extrapolate: 'clamp',
  });

  // Optimized interpolations for smoother performance
  const interpolatedColor = colorChangeAnim.interpolate({
    inputRange: [0, 1],
    outputRange: ['#BFC5F5', '#FFFFFF'],
    extrapolate: 'clamp',
  });

  const navigation = useNavigation();

  const handleLoginSignUp = () => {
    // Accept any username or password without validation
    console.log('Login successful with:', { email, password });
    navigation.navigate('Onboarding');
  };

  

  WebBrowser.maybeCompleteAuthSession();

  const [request, response, promptAsync] = Google.useIdTokenAuthRequest({
    clientId: '714798843725-ciifbjo4d2skj248cma97rjsjciduvsm.apps.googleusercontent.com',
    redirectUri: 'http://localhost:8081/expo-auth-session',
  });

  useEffect(() => {
    if (response?.type === 'success') {
      const { id_token } = response.params;
      // Send id_token to backend for login
      fetch('http://localhost:8000/api/v1/auth/google-login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ token: id_token }),
      })
        .then((res) => {
          if (!res.ok) {
            throw new Error('Google login failed');
          }
          return res.json();
        })
        .then(async (data) => {
          // Handle successful login, e.g., store tokens, navigate
          console.log('Login success:', data);
          await AsyncStorage.setItem('jwtToken', data.jwt_token);
          navigation.navigate('Home');
        })
        .catch((error) => {
          Alert.alert('Login Error', error.message);
        });
    }
  }, [response]);

  const handleGoogleSignIn = () => {
    promptAsync();
  };

  const handleFacebookSignIn = () => {
    console.log('Continue with Facebook');
  };

  return (
    <View style={styles.mainContainer}>
      {/* Animation Container */}
      <Animated.View
        style={[
          styles.animationContainer,
          {
            opacity: animationContainerAnim,
            zIndex: showLogin ? 0 : 1,
          },
        ]}
      >
        <View style={styles.animationContent}>
          <Animated.View
            style={[
              styles.imageContainer,
              {
                opacity: imagesVisibilityAnim,
              },
            ]}
          >
            <Animated.Image
              source={require('./assets/img1.png')}
              style={[
                styles.rotatedImage,
                {
                  opacity: topImageAnim,
                  transform: [
                    { rotate: '180deg' },
                    {
                      scale: topImageAnim.interpolate({
                        inputRange: [0, 1],
                        outputRange: [0.3, 1],
                      }),
                    },
                  ],
                },
              ]}
              resizeMode="contain"
            />
          </Animated.View>

          {/* Logo Animation */}
          <View style={styles.logoContainer}>
            <Animated.View
              style={[
                styles.logoWrapper,
                {
                  transform: [
                    {
                      scale: logoScaleAnim.interpolate({
                        inputRange: [0, 1],
                        outputRange: [0.8, 1],
                      }),
                    },
                  ],
                },
              ]}
            >
              {/* Animated Diamonds */}
              <Animated.View
                style={[
                  styles.diamond,
                  { backgroundColor: interpolatedColor },
                  styles.diamondTop,
                  {
                    opacity: diamond1Anim,
                    transform: [
                      { rotate: '45deg' },
                      {
                        translateX: diamond1Anim.interpolate({
                          inputRange: [0, 1],
                          outputRange: [-150, 0],
                        }),
                      },
                      {
                        translateY: diamond1Anim.interpolate({
                          inputRange: [0, 1],
                          outputRange: [-150, 0],
                        }),
                      },
                      {
                        scale: diamond1Anim.interpolate({
                          inputRange: [0, 0.5, 1],
                          outputRange: [0, 1.2, 1],
                        }),
                      },
                    ],
                  },
                ]}
              />

              <Animated.View
                style={[
                  styles.diamond,
                  { backgroundColor: interpolatedColor },
                  styles.diamondRight,
                  {
                    opacity: diamond2Anim,
                    transform: [
                      { rotate: '45deg' },
                      {
                        translateX: diamond2Anim.interpolate({
                          inputRange: [0, 1],
                          outputRange: [150, 0],
                        }),
                      },
                      {
                        translateY: diamond2Anim.interpolate({
                          inputRange: [0, 1],
                          outputRange: [-150, 0],
                        }),
                      },
                      {
                        scale: diamond2Anim.interpolate({
                          inputRange: [0, 0.5, 1],
                          outputRange: [0, 1.2, 1],
                        }),
                      },
                    ],
                  },
                ]}
              />

              <Animated.View
                style={[
                  styles.diamond,
                  { backgroundColor: interpolatedColor },
                  styles.diamondBottom,
                  {
                    opacity: diamond3Anim,
                    transform: [
                      { rotate: '45deg' },
                      {
                        translateX: diamond3Anim.interpolate({
                          inputRange: [0, 1],
                          outputRange: [-150, 0],
                        }),
                      },
                      {
                        translateY: diamond3Anim.interpolate({
                          inputRange: [0, 1],
                          outputRange: [150, 0],
                        }),
                      },
                      {
                        scale: diamond3Anim.interpolate({
                          inputRange: [0, 0.5, 1],
                          outputRange: [0, 1.2, 1],
                        }),
                      },
                    ],
                  },
                ]}
              />

              <Animated.View
                style={[
                  styles.diamond,
                  { backgroundColor: interpolatedColor },
                  styles.diamondLeft,
                  {
                    opacity: diamond4Anim,
                    transform: [
                      { rotate: '45deg' },
                      {
                        translateX: diamond4Anim.interpolate({
                          inputRange: [0, 1],
                          outputRange: [150, 0],
                        }),
                      },
                      {
                        translateY: diamond4Anim.interpolate({
                          inputRange: [0, 1],
                          outputRange: [150, 0],
                        }),
                      },
                      {
                        scale: diamond4Anim.interpolate({
                          inputRange: [0, 0.5, 1],
                          outputRange: [0, 1.2, 1],
                        }),
                      },
                    ],
                  },
                ]}
              />
            </Animated.View>

            <Animated.Text
              style={[
                styles.logoText,
                {
                  color: interpolatedColor,
                  opacity: textAnim,
                  transform: [
                    {
                      translateY: textAnim.interpolate({
                        inputRange: [0, 1],
                        outputRange: [20, 0],
                      }),
                    },
                    {
                      scale: textAnim.interpolate({
                        inputRange: [0, 1],
                        outputRange: [0.8, 1],
                      }),
                    },
                  ],
                },
              ]}
            >
              VerbX AI
            </Animated.Text>
          </View>

          {/* Other positioned images */}
          <Animated.View
            style={[
              styles.leftImageContainer,
              { opacity: imagesVisibilityAnim },
            ]}
          >
            <Animated.Image
              source={require('./assets/img2.png')}
              style={[
                styles.leftImage,
                {
                  opacity: leftImageAnim,
                  transform: [
                    {
                      scale: leftImageAnim.interpolate({
                        inputRange: [0, 1],
                        outputRange: [0.3, 1],
                      }),
                    },
                  ],
                },
              ]}
              resizeMode="contain"
            />
          </Animated.View>

          <Animated.View
            style={[
              styles.rightImageContainer,
              { opacity: imagesVisibilityAnim },
            ]}
          >
            <Animated.Image
              source={require('./assets/img3.png')}
              style={[
                styles.rightImage,
                {
                  opacity: rightImageAnim,
                  transform: [
                    {
                      scale: rightImageAnim.interpolate({
                        inputRange: [0, 1],
                        outputRange: [0.3, 1],
                      }),
                    },
                  ],
                },
              ]}
              resizeMode="contain"
            />
          </Animated.View>

          <Animated.View
            style={[
              styles.bottomImageContainer,
              { opacity: imagesVisibilityAnim },
            ]}
          >
            <Animated.Image
              source={require('./assets/img4.png')}
              style={[
                styles.bottomImage,
                {
                  opacity: bottomImageAnim,
                  transform: [
                    { rotate: '180deg' },
                    {
                      scale: bottomImageAnim.interpolate({
                        inputRange: [0, 1],
                        outputRange: [0.3, 1],
                      }),
                    },
                  ],
                },
              ]}
              resizeMode="contain"
            />
          </Animated.View>
        </View>
      </Animated.View>

      {/* Login Container */}
      <Animated.View
        style={[
          styles.loginContainer,
          {
            opacity: loginFadeAnim,
            zIndex: showLogin ? 1 : 0,
            transform: [{ scale: subtleScale }],
          },
        ]}
      >
        <KeyboardAvoidingView
          style={styles.container}
          behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
          keyboardVerticalOffset={Platform.OS === 'ios' ? 0 : 20}
        >
          <StatusBar barStyle="dark-content" backgroundColor="#BFC5F5" />
          
          <View style={styles.loginLogoContainer}>
            <View style={styles.diamondIcon}>
              <View style={[styles.smallDiamond, styles.smallDiamond1]} />
              <View style={[styles.smallDiamond, styles.smallDiamond2]} />
              <View style={[styles.smallDiamond, styles.smallDiamond3]} />
              <View style={[styles.smallDiamond, styles.smallDiamond4]} />
            </View>
          </View>

          <Text style={styles.title}>Log In or Sign Up</Text>

          {/* Email Input */}
          <View
            style={[
              styles.inputWrapper,
              isEmailFocused && styles.inputWrapperFocused,
            ]}
          >
            <TextInput
              style={styles.input}
              placeholder="email@gmail.com"
              placeholderTextColor="#999"
              keyboardType="email-address"
              autoCapitalize="none"
              value={email}
              onChangeText={setEmail}
              onFocus={() => setIsEmailFocused(true)}
              onBlur={() => setIsEmailFocused(false)}
              underlineColorAndroid="transparent"
              selectionColor="#333"
            />
          </View>

          {/* Password Input */}
          <View
            style={[
              styles.inputWrapper,
              isPasswordFocused && styles.inputWrapperFocused,
            ]}
          >
            <TextInput
              style={styles.input}
              placeholder="Password"
              placeholderTextColor="#999"
              secureTextEntry={!showPassword}
              autoCapitalize="none"
              value={password}
              onChangeText={setPassword}
              onFocus={() => setIsPasswordFocused(true)}
              onBlur={() => setIsPasswordFocused(false)}
              underlineColorAndroid="transparent"
              selectionColor="#333"
            />
            <TouchableOpacity
              onPress={() => setShowPassword(!showPassword)}
              style={styles.togglePasswordButton}
            >
              <Text style={styles.togglePasswordText}>
                {showPassword ? 'Hide' : 'Show'}
              </Text>
            </TouchableOpacity>
          </View>

          <TouchableOpacity
            style={[
              styles.primaryButton,
              isButtonPressed && styles.primaryButtonPressed,
            ]}
            onPress={handleLoginSignUp}
            onPressIn={() => setIsButtonPressed(true)}
            onPressOut={() => setIsButtonPressed(false)}
            activeOpacity={1}
          >
            <Text style={styles.primaryButtonText}>Log In or Sign up</Text>
          </TouchableOpacity>

          <Text style={styles.orText}>or</Text>

          <TouchableOpacity
            style={[
              styles.socialButton,
              isGoogleButtonPressed && styles.socialButtonPressed,
            ]}
            onPress={handleGoogleSignIn}
            onPressIn={() => setIsGoogleButtonPressed(true)}
            onPressOut={() => setIsGoogleButtonPressed(false)}
            activeOpacity={1}
          >
            <Image
              source={require('./assets/google.png')}
              style={styles.socialIcon}
            />
            <Text style={styles.socialButtonText}>Continue with Google</Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[
              styles.socialButton,
              isFacebookButtonPressed && styles.socialButtonPressed,
            ]}
            onPress={handleFacebookSignIn}
            onPressIn={() => setIsFacebookButtonPressed(true)}
            onPressOut={() => setIsFacebookButtonPressed(false)}
            activeOpacity={1}
          >
            <Image
              source={require('./assets/Facebook.png')}
              style={styles.socialIcon}
            />
            <Text style={styles.socialButtonText}>Continue with Facebook</Text>
          </TouchableOpacity>

          <View style={styles.bottomSwirlContainer}>
            <Text style={styles.bottomSwirlText}>~</Text>
          </View>
        </KeyboardAvoidingView>
      </Animated.View>
    </View>
  );
};

const styles = StyleSheet.create({
  mainContainer: {
    flex: 1,
  },
  
  // Animation styles
  animationContainer: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: '#0C0D11',
  },
  animationContent: {
    flex: 1,
  },
  imageContainer: {
    alignItems: 'center',
    justifyContent: 'center',
    paddingTop: 0,
  },
  rotatedImage: {
    width: screenWidth * 0.8,
    height: 80,
    transform: [{ rotate: '180deg' }],
  },
  leftImageContainer: {
    position: 'absolute',
    left: 0,
    top: 310,
  },
  leftImage: {
    width: 80,
    height: 200,
  },
  rightImageContainer: {
    position: 'absolute',
    right: 0,
    top: 310,
  },
  rightImage: {
    width: 80,
    height: 200,
  },
  bottomImageContainer: {
    position: 'absolute',
    bottom: 0,
    left: 0,
    right: 0,
    alignItems: 'center',
  },
  bottomImage: {
    width: 150,
    height: 80,
    transform: [{ rotate: '180deg' }],
  },
  logoContainer: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    justifyContent: 'center',
    alignItems: 'center',
  },
  logoWrapper: {
    width: 100,
    height: 100,
    position: 'relative',
  },
  diamond: {
    position: 'absolute',
    width: 35,
    height: 35,
    borderRadius: 8,
  },
  diamondTop: {
    top: 0,
    left: 32.5,
  },
  diamondRight: {
    top: 32.5,
    right: 0,
  },
  diamondBottom: {
    bottom: 0,
    left: 32.5,
  },
  diamondLeft: {
    top: 32.5,
    left: 0,
  },
  logoText: {
    fontSize: 24,
    fontWeight: 'bold',
    textAlign: 'center',
    marginTop: 80,
    letterSpacing: 1,
  },

  // Login styles
  loginContainer: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
  },
  container: {
    flex: 1,
    backgroundColor: '#BFC5F5',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingTop: StatusBar.currentHeight || 50,
    justifyContent: 'center',
  },
  loginLogoContainer: {
    marginBottom: 40,
    marginTop: -80,
  },
  diamondIcon: {
    width: 100,
    height: 100,
    justifyContent: 'center',
    alignItems: 'center',
  },
  smallDiamond: {
    position: 'absolute',
    width: 20,
    height: 20,
    backgroundColor: '#333',
    transform: [{ rotate: '45deg' }],
    borderRadius: 4,
  },
  smallDiamond1: { top: 25, left: 40 },
  smallDiamond2: { top: 40, right: 25 },
  smallDiamond3: { bottom: 25, left: 40 },
  smallDiamond4: { top: 40, left: 25 },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#333',
    marginBottom: 40,
  },
  inputWrapper: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'white',
    borderRadius: 12,
    width: '100%',
    maxWidth: 350,
    marginBottom: 15,
    paddingHorizontal: 15,
    height: 55,
  },
  inputWrapperFocused: {
    borderColor: 'white',
    borderWidth: 0,
  },
  input: {
    flex: 1,
    height: '100%',
    fontSize: 16,
    color: '#333',
    outline: 'none',
  },
  togglePasswordButton: {
    paddingLeft: 10,
  },
  togglePasswordText: {
    fontSize: 16,
    color: '#999',
    fontWeight: '600',
  },
  primaryButton: {
    backgroundColor: '#0C0D11',
    borderRadius: 12,
    width: '100%',
    maxWidth: 350,
    paddingVertical: 18,
    alignItems: 'center',
    marginTop: 10,
  },
  primaryButtonPressed: {
    backgroundColor: '#666666',
  },
  primaryButtonText: {
    color: 'white',
    fontSize: 18,
    fontWeight: '600',
  },
  orText: {
    color: '#666',
    fontSize: 16,
    marginVertical: 25,
  },
  socialButton: {
    backgroundColor: 'white',
    borderRadius: 12,
    width: '100%',
    maxWidth: 350,
    paddingVertical: 15,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 15,
    borderWidth: 1,
    borderColor: '#E0E0E0',
  },
  socialButtonPressed: {
    backgroundColor: '#F5F5F5',
    borderColor: '#CCCCCC',
  },
  socialIcon: {
    width: 24,
    height: 24,  
    marginRight: 10,
  },
  socialButtonText: { 
    color: '#333',
    fontSize: 16,
    fontWeight: '600',
  },
  bottomSwirlContainer: {
    position: 'absolute',
    bottom: 0,
    right: 0,
    width: width * 0.4,
    height: width * 0.4,
    justifyContent: 'flex-end',
    alignItems: 'flex-end',
    overflow: 'hidden',
  },
  bottomSwirlText: {
    fontSize: 150,
    color: 'rgba(0,0,0,0.1)',
    transform: [{ rotate: '-20deg' }, { translateY: 50 }, { translateX: 20 }],
  },
});

export default CombinedScreen;  
